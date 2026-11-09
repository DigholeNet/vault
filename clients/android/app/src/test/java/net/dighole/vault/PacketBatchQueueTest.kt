// SPDX-License-Identifier: MIT
package net.dighole.vault

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class PacketBatchQueueTest {
    @Test
    fun batchOrder() = runBlocking {
        withTimeout(5000) {
            val queue = PacketBatchQueue()
            val first = listOf(byteArrayOf(1), byteArrayOf(2, 3))
            val second = listOf(byteArrayOf(4))
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(emptyList()))
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(first))
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(second))
            // The entire batch and its arrays are transferred without copying.
            assertSame(first, queue.receive())
            assertSame(second, queue.receive())
            queue.close()
        }
    }

    @Test
    fun packetLimit() = runBlocking {
        withTimeout(5000) {
            val queue = PacketBatchQueue(4)
            val first = List(3) { byteArrayOf(it.toByte()) }
            val overflow = listOf(byteArrayOf(3), byteArrayOf(4))
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(first))
            assertEquals(PacketBatchQueue.SendResult.FULL, queue.trySend(overflow))
            assertEquals(PacketBatchQueue.SendResult.FULL, queue.trySend(overflow))
            assertSame(first, queue.receive())
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(first))
            val prefix = queue.receive()
            assertEquals(1, prefix.size)
            assertSame(overflow[0], prefix[0])
            assertSame(first, queue.receive())
            // Receiving both batches restores the complete packet budget.
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(List(4) { byteArrayOf(5) }))
            queue.close()
        }
    }

    @Test
    fun cancelledReceive() = runBlocking {
        withTimeout(5000) {
            val queue = PacketBatchQueue(2)
            val batch = listOf(byteArrayOf(1), byteArrayOf(2))
            val receiver = launch(start = CoroutineStart.UNDISPATCHED) {
                queue.receive()
                fail("Cancelled receive must not deliver the batch")
            }
            // Resume the suspended receiver, then cancel it before its continuation runs.
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(batch))
            receiver.cancel()
            receiver.join()
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(batch))
            assertEquals(PacketBatchQueue.SendResult.FULL, queue.trySend(batch))
            assertSame(batch, queue.receive())
            queue.close()
        }
    }

    @Test
    fun closeDrops() = runBlocking {
        withTimeout(5000) {
            val queue = PacketBatchQueue(2)
            val batch = listOf(byteArrayOf(1), byteArrayOf(2))
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(batch))
            queue.close()
            queue.close()
            assertTrue(queue.isClosed)
            assertEquals(PacketBatchQueue.SendResult.CLOSED, queue.trySend(batch))
            try {
                queue.receive()
                fail("Closed queue must discard buffered packets")
            } catch (_: CancellationException) {
                // Teardown cancels the channel rather than draining stale packets.
            }
        }
    }

    @Test
    fun concurrentLimit() = runBlocking {
        withTimeout(5000) {
            val queue = PacketBatchQueue()
            val accepted = AtomicInteger()
            val batch = List(32) { byteArrayOf(it.toByte()) }
            List(8) {
                launch(Dispatchers.Default) {
                    repeat(32) {
                        if (queue.trySend(batch) == PacketBatchQueue.SendResult.ACCEPTED) {
                            accepted.addAndGet(batch.size)
                        }
                    }
                }
            }.joinAll()
            assertEquals(1024, accepted.get())
            repeat(32) { assertSame(batch, queue.receive()) }
            assertEquals(PacketBatchQueue.SendResult.ACCEPTED, queue.trySend(batch))
            queue.close()
        }
    }
}
