// SPDX-License-Identifier: MIT
package net.dighole.vault

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals

class SessionGateTest {
    private class Resource : Closeable {
        var closed = false
        override fun close() { closed = true }
    }

    @Test
    fun supersededTun() = runBlocking {
        withTimeout(5000) {
            val gate = SessionGate()
            val token = gate.begin()
            var sequence = 1L
            var assignedAddress: String? = "A"
            val old = Resource()
            var activeTun: Resource? = old
            var publishedTun = old
            val stale = Resource()
            val replacement = Resource()
            val creating = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val first = launch(Dispatchers.Default) {
                gate.configure {
                    creating.complete(Unit)
                    resume.await()
                    // Android establishes B: A stays open but stops routing.
                    activeTun = stale
                    gate.commit(token, stale,
                        condition = { sequence == 1L },
                        onCreated = { assignedAddress = null }
                    ) {
                        publishedTun = it
                        assignedAddress = "B"
                    }
                    if (stale.closed) activeTun = null
                }
            }
            creating.await()
            gate.update(token) { sequence = 2L }
            val second = launch(start = CoroutineStart.UNDISPATCHED) {
                gate.configure {
                    // Latest assignment returns to A. An open fd is insufficient.
                    if (!publishedTun.closed && assignedAddress == "A") return@configure
                    activeTun = replacement
                    gate.commit(token, replacement,
                        condition = { sequence == 2L },
                        onCreated = { assignedAddress = null }
                    ) {
                        publishedTun.close()
                        publishedTun = it
                        assignedAddress = "A"
                    }
                }
            }
            resume.complete(Unit)
            first.join()
            second.join()
            assertTrue(stale.closed)
            assertTrue(old.closed)
            assertFalse(replacement.closed)
            assertTrue(publishedTun === replacement)
            assertTrue(activeTun === replacement)
            assertEquals("A", assignedAddress)
        }
    }

    @Test
    fun staleCreation() {
        val gate = SessionGate()
        val old = gate.begin()
        gate.stop { }
        val current = gate.begin()
        var assignedAddress: String? = "new session"
        val stale = Resource()
        assertFalse(gate.commit(old, stale, onCreated = { assignedAddress = null }) {
            error("old interface published")
        })
        assertTrue(stale.closed)
        assertEquals("new session", assignedAddress)
        assertTrue(gate.update(current) { })
    }

    @Test
    fun supersededConfig() = runBlocking {
        withTimeout(5000) {
            val gate = SessionGate()
            val token = gate.begin()
            var sequence = 1L
            val entered = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val stale = Resource()
            val events = mutableListOf<String>()
            val first = launch(Dispatchers.Default) {
                gate.configure {
                    entered.complete(Unit)
                    resume.await()
                    gate.commit(token, stale, condition = { sequence == 1L }) {
                        events.add("stale configured")
                    }
                    // A failure from this same obsolete request must also be ignored.
                    gate.updateIf(token, { sequence == 1L }) { events.add("stop service") }
                }
            }
            entered.await()
            gate.update(token) { sequence = 2L }
            val second = launch(start = CoroutineStart.UNDISPATCHED) {
                gate.configure {
                    gate.commit(token, Resource(), condition = { sequence == 2L }) {
                        events.add("current configured")
                    }
                }
            }
            resume.complete(Unit)
            first.join()
            second.join()
            assertTrue(stale.closed)
            assertEquals(listOf("current configured"), events)
        }
    }

    @Test
    fun latePacket() = runBlocking {
        withTimeout(5000) {
            val gate = SessionGate()
            val old = gate.begin()
            val entered = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val oldQueue = mutableListOf<String>()
            val newQueue = mutableListOf<String>()
            var queue = oldQueue
            val callback = launch(Dispatchers.Default) {
                entered.complete(Unit)
                resume.await()
                gate.update(old) { queue.add("old packet") }
            }
            entered.await()
            gate.stop { }
            val current = gate.begin()
            gate.update(current) { queue = newQueue }
            resume.complete(Unit)
            callback.join()
            gate.update(current) { queue.add("new packet") }
            assertTrue(oldQueue.isEmpty())
            assertEquals(listOf("new packet"), newQueue)
        }
    }

    @Test
    fun serialConfig() = runBlocking {
        withTimeout(5000) {
            val gate = SessionGate()
            val token = gate.begin()
            val entered = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val events = mutableListOf<String>()
            val first = launch(Dispatchers.Default) {
                gate.configure {
                    events.add("create first")
                    entered.complete(Unit)
                    resume.await()
                    gate.commit(token, Resource()) { events.add("publish first") }
                }
            }
            entered.await()
            // UNDISPATCHED runs up to the contested lock before returning.
            val second = launch(start = CoroutineStart.UNDISPATCHED) {
                gate.configure {
                    events.add("create second")
                    gate.commit(token, Resource()) { events.add("publish second") }
                }
            }
            assertEquals(listOf("create first"), events)
            resume.complete(Unit)
            first.join()
            second.join()
            assertEquals(listOf("create first", "publish first", "create second", "publish second"), events)
        }
    }

    @Test
    fun stopDuringConfig() = runBlocking {
        withTimeout(5000) {
            val gate = SessionGate()
            val token = gate.begin()
            val entered = CompletableDeferred<Unit>()
            val resume = CompletableDeferred<Unit>()
            val resource = Resource()
            val worker = launch(Dispatchers.Default) {
                gate.configure {
                    entered.complete(Unit)
                    resume.await()
                    gate.commit(token, resource) { error("stopped TUN published") }
                }
            }
            entered.await()
            // Stop must complete while configuration is still blocked.
            gate.stop { }
            resume.complete(Unit)
            worker.join()
            assertTrue(resource.closed)
        }
    }

    @Test
    fun lateRestart() {
        val gate = SessionGate()
        val token = gate.begin()
        val waiting = CountDownLatch(1)
        val timeout = CountDownLatch(1)
        val replacement = Resource()
        val restarted = AtomicBoolean(false)
        val watchdog = thread {
            waiting.countDown()
            check(timeout.await(5, TimeUnit.SECONDS))
            // The watchdog resumes after handover, even if cancellation was late.
            gate.update(token) {
                replacement.close()
                restarted.set(true)
            }
        }
        assertTrue(waiting.await(5, TimeUnit.SECONDS))
        gate.stop { }
        gate.begin()
        timeout.countDown()
        watchdog.join(5000)
        assertFalse(watchdog.isAlive)
        assertFalse(replacement.closed)
        assertFalse(restarted.get())
    }

    @Test
    fun lateCreate() {
        val gate = SessionGate()
        val token = gate.begin()
        val creating = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val resource = Resource()
        var published = false
        val worker = thread {
            creating.countDown()
            check(resume.await(5, TimeUnit.SECONDS))
            gate.commit(token, resource) { published = true }
        }
        assertTrue(creating.await(5, TimeUnit.SECONDS))
        gate.stop { }
        resume.countDown()
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertTrue(resource.closed)
        assertFalse(published)
    }

    @Test
    fun oldSession() {
        val gate = SessionGate()
        val old = gate.begin()
        val current = gate.begin()
        val stale = Resource()
        assertFalse(gate.commit(old, stale) { error("stale session published") })
        assertTrue(stale.closed)
        val valid = Resource()
        assertTrue(gate.commit(current, valid) { })
        assertFalse(valid.closed)
        assertFalse(gate.update(old) { error("old error modified new session") })
    }

    @Test
    fun stopAfterCommit() {
        val gate = SessionGate()
        val token = gate.begin()
        val publishing = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val connected = AtomicBoolean(false)
        val resource = Resource()
        val worker = thread {
            gate.commit(token, resource) {
                publishing.countDown()
                check(resume.await(5, TimeUnit.SECONDS))
                connected.set(true)
            }
        }
        assertTrue(publishing.await(5, TimeUnit.SECONDS))
        val stopper = thread { gate.stop { resource.close(); connected.set(false) } }
        resume.countDown()
        worker.join(5000)
        stopper.join(5000)
        assertFalse(worker.isAlive)
        assertFalse(stopper.isAlive)
        assertTrue(resource.closed)
        assertFalse(connected.get())
    }
}
