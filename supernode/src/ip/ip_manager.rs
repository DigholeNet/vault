// SPDX-License-Identifier: MIT
use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use sqlite::{Connection, State, Statement};
use tracing::{debug, error, info};

use vault_core::{PeerId, Time, TimeSource};

use crate::{
    error::StorageError,
    ip::pool::{Ipv4Pool, Ipv6Pool},
};
const IP_LEASE_TIMEOUT: Time = 300;

#[derive(Debug)]
pub struct IpAddress {
    pub id: PeerId,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub gmt_create: Time,
    pub gmt_modify: Time,
}

pub trait Storage {
    /// Look up the IP address already assigned to a peer id.
    fn find_by_id(&self, id: &PeerId) -> anyhow::Result<IpAddress>;

    /// Remove expired IP leases.
    fn clean_expired_items<F: FnMut(&IpAddress)>(&self, f: F) -> anyhow::Result<()>;

    /// Insert an IP lease record.
    fn insert(
        &self,
        id: &PeerId,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> anyhow::Result<()>;

    /// Remove a lease record entirely.
    fn delete(&self, id: &PeerId) -> anyhow::Result<()>;

    /// Refresh a lease's last-active timestamp.
    fn update(&self, id: &PeerId) -> anyhow::Result<()>;
}

struct SqliteStorage<T: TimeSource> {
    connection: Connection,
    _ts: PhantomData<T>,
}

impl<T: TimeSource> SqliteStorage<T> {
    fn new() -> anyhow::Result<Self> {
        let connection = sqlite::open(":memory:")?;

        let query = "
        CREATE TABLE peer (id VARCHAR(32), ipv4 VARCHAR(32), ipv6 VARCHAR(64),  gmt_create TIMESTAMP, gmt_modify TIMESTAMP);
        CREATE UNIQUE INDEX index_id on peer (id);
        CREATE INDEX index_gmt_modify on peer (gmt_modify);
        ";
        connection.execute(query)?;

        Ok(Self {
            connection,
            _ts: PhantomData,
        })
    }

    fn convert(statement: &mut Statement<'_>) -> anyhow::Result<IpAddress> {
        let id = statement.read::<String, _>("id")?;
        let ipv4 = statement.read::<String, _>("ipv4")?;
        let ipv6 = statement.read::<String, _>("ipv6")?;
        let gmt_create = statement.read::<i64, _>("gmt_create")?;
        let gmt_modify = statement.read::<i64, _>("gmt_modify")?;

        let mut buffer = [0u8; 16];
        hex::decode_to_slice(id, &mut buffer)?;

        let id = PeerId(buffer);
        let ipv4 = if ipv4.is_empty() {
            None
        } else {
            Some(ipv4.parse()?)
        };

        let ipv6 = if ipv6.is_empty() {
            None
        } else {
            Some(ipv6.parse()?)
        };

        Ok(IpAddress {
            id,
            ipv4,
            ipv6,
            gmt_create,
            gmt_modify,
        })
    }
}

impl<T: TimeSource> Storage for SqliteStorage<T> {
    fn find_by_id(&self, id: &PeerId) -> anyhow::Result<IpAddress> {
        let query = "SELECT id,ipv4,ipv6,gmt_create,gmt_modify FROM peer WHERE id =?";
        let id_str = hex::encode(id.0);
        let mut statement = self.connection.prepare(query)?;
        statement.bind((1, id_str.as_str()))?;
        if let Ok(State::Row) = statement.next() {
            return SqliteStorage::<T>::convert(&mut statement);
        }
        Err(anyhow::anyhow!(StorageError::NotFound(id_str)))
    }

    fn clean_expired_items<F: FnMut(&IpAddress)>(&self, mut f: F) -> anyhow::Result<()> {
        let time = T::now() - IP_LEASE_TIMEOUT;

        let query = "SELECT id,ipv4,ipv6,gmt_create,gmt_modify FROM peer WHERE gmt_modify < ?";
        let mut select_stmt = self.connection.prepare(query)?;
        select_stmt.bind((1, time))?;

        let mut expired_items: Vec<IpAddress> = Vec::new();
        while let State::Row = select_stmt.next()? {
            expired_items.push(SqliteStorage::<T>::convert(&mut select_stmt)?);
        }
        drop(select_stmt);

        for item in expired_items {
            f(&item);
            let id_str = hex::encode(item.id.0);
            let delete_query = "DELETE FROM peer WHERE id = ?";
            let mut delete_stmt = self.connection.prepare(delete_query)?;
            delete_stmt.bind((1, id_str.as_str()))?;
            match delete_stmt.next()? {
                State::Done => {}
                State::Row => return Err(anyhow::anyhow!("DELETE unexpectedly returned row")),
            }
            drop(delete_stmt);
            info!(
                "Clear expired peer: {}->{:?}/{:?}",
                id_str, item.ipv4, item.ipv6
            );
        }

        Ok(())
    }

    fn insert(
        &self,
        id: &PeerId,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> anyhow::Result<()> {
        let time = T::now();
        let id_str = hex::encode(id.0);

        let ipv4 = ipv4.map_or("".to_string(), |ip| ip.to_string());
        let ipv6 = ipv6.map_or("".to_string(), |ip| ip.to_string());

        let query = "INSERT INTO peer(id,ipv4,ipv6,gmt_create,gmt_modify) VALUES(?, ?, ?, ?, ?)";
        let mut statement = self.connection.prepare(query)?;
        statement.bind((1, id_str.as_str()))?;
        statement.bind((2, ipv4.as_str()))?;
        statement.bind((3, ipv6.as_str()))?;
        statement.bind((4, time))?;
        statement.bind((5, time))?;
        match statement.next()? {
            State::Done => Ok(()),
            State::Row => Err(anyhow::anyhow!("Unexpected row from INSERT")),
        }
    }

    fn delete(&self, id: &PeerId) -> anyhow::Result<()> {
        let id_str = hex::encode(id.0);
        let query = "DELETE FROM peer WHERE id = ?";
        let mut statement = self.connection.prepare(query)?;
        statement.bind((1, id_str.as_str()))?;
        match statement.next()? {
            State::Done => Ok(()),
            State::Row => Err(anyhow::anyhow!("Unexpected row from DELETE")),
        }
    }

    fn update(&self, id: &PeerId) -> anyhow::Result<()> {
        let time = T::now();
        let id_str = hex::encode(id.0);
        let query = "UPDATE peer set gmt_modify = ? WHERE id = ?";
        let mut statement = self.connection.prepare(query)?;
        statement.bind((1, time))?;
        statement.bind((2, id_str.as_str()))?;
        match statement.next()? {
            State::Done => Ok(()),
            State::Row => Err(anyhow::anyhow!("Unexpected row from UPDATE")),
        }
    }
}

pub struct IpManager<T: TimeSource> {
    storage: SqliteStorage<T>,
    ipv4_allocator: Option<Ipv4Pool>,
    ipv6_allocator: Option<Ipv6Pool>,
}

impl<T: TimeSource> IpManager<T> {
    pub fn new(
        ipv4_allocator: Option<Ipv4Pool>,
        ipv6_allocator: Option<Ipv6Pool>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            storage: SqliteStorage::<T>::new()?,
            ipv4_allocator,
            ipv6_allocator,
        })
    }

    pub fn clean_expired_items(&mut self) -> anyhow::Result<()> {
        let ipv4_pool = &mut self.ipv4_allocator;
        let ipv6_pool = &mut self.ipv6_allocator;

        self.storage.clean_expired_items(|ip| {
            if let Some(ipv4) = &ip.ipv4
                && let Some(pool) = ipv4_pool
                && let Err(e) = pool.release(*ipv4)
            {
                error!("Release ipv4 error: {:?}", e);
            }

            if let Some(ipv6) = &ip.ipv6
                && let Some(pool) = ipv6_pool
                && let Err(e) = pool.release(*ipv6)
            {
                error!("Release ipv6 error: {:?}", e);
            }
        })?;

        Ok(())
    }

    pub fn update(&self, id: &PeerId) -> anyhow::Result<()> {
        self.storage.update(id)
    }

    pub fn assign(&mut self, id: &PeerId) -> anyhow::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        if let Ok(r) = self.storage.find_by_id(id) {
            debug!(
                "use old ip: {}->{:?}/{:?} gmt_create:{}, gmt_modify:{}",
                hex::encode(r.id.0),
                r.ipv4,
                r.ipv6,
                r.gmt_create,
                r.gmt_modify
            );
            return Ok((r.ipv4, r.ipv6));
        }

        let ipv4 = self
            .ipv4_allocator
            .as_mut()
            .and_then(|a| match a.allocate() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    error!("IPv4 allocation failed: {}", e);
                    None
                }
            });
        let ipv6 = self
            .ipv6_allocator
            .as_mut()
            .and_then(|a| match a.allocate() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    error!("IPv6 allocation failed: {}", e);
                    None
                }
            });

        if ipv4.is_none() && ipv6.is_none() {
            return Err(anyhow::anyhow!(StorageError::IpAssign));
        }

        debug!("assign ip: {}->{:?}/{:?}", hex::encode(id.0), ipv4, ipv6);

        self.storage.insert(id, ipv4, ipv6)?;

        Ok((ipv4, ipv6))
    }

    pub fn release(&mut self, ip: IpAddr) -> anyhow::Result<()> {
        match ip {
            IpAddr::V4(ipv4_addr) => {
                if let Some(m) = &mut self.ipv4_allocator {
                    m.release(ipv4_addr)?;
                }
            }
            IpAddr::V6(ipv6_addr) => {
                if let Some(m) = &mut self.ipv6_allocator {
                    m.release(ipv6_addr)?;
                }
            }
        }
        Ok(())
    }

    /// Undo an assignment after a failed handshake: delete the lease row and
    /// return its addresses to the pools. Releasing only into the pools would
    /// leave the address leased to this id while also being assignable to
    /// another client.
    pub fn revoke(&mut self, id: &PeerId) -> anyhow::Result<()> {
        if let Ok(r) = self.storage.find_by_id(id) {
            if let Some(ipv4) = r.ipv4
                && let Err(e) = self.release(IpAddr::V4(ipv4))
            {
                error!("Release ipv4 error: {:?}", e);
            }
            if let Some(ipv6) = r.ipv6
                && let Err(e) = self.release(IpAddr::V6(ipv6))
            {
                error!("Release ipv6 error: {:?}", e);
            }
            self.storage.delete(id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::ip::{IpManager, Ipv4Cidr, Ipv4Pool, Ipv6Cidr, Ipv6Pool};
    use crate::mock_time::{MockTime, advance, lock_clock};

    fn peer_id(n: u8) -> PeerId {
        PeerId([n; 16])
    }

    fn dual_stack_manager() -> IpManager<MockTime> {
        let ipv4 = Ipv4Pool::new(Ipv4Cidr::from_str("10.0.0.0/24").unwrap());
        let ipv6 = Ipv6Pool::new(Ipv6Cidr::from_str("fd00::/64").unwrap());
        IpManager::<MockTime>::new(Some(ipv4), Some(ipv6)).unwrap()
    }

    #[test]
    fn test_assign_dual_stack_and_idempotent() {
        let _guard = lock_clock(1_000);
        let mut manager = dual_stack_manager();

        let (ipv4, ipv6) = manager.assign(&peer_id(1)).unwrap();
        assert_eq!(ipv4, Some(Ipv4Addr::from_str("10.0.0.1").unwrap()));
        assert_eq!(ipv6, Some(Ipv6Addr::from_str("fd00::1").unwrap()));

        // Repeat assign returns the existing lease, not a new allocation.
        let again = manager.assign(&peer_id(1)).unwrap();
        assert_eq!(again, (ipv4, ipv6));

        let next = manager.assign(&peer_id(2)).unwrap();
        assert_eq!(next.0, Some(Ipv4Addr::from_str("10.0.0.2").unwrap()));
        assert_eq!(next.1, Some(Ipv6Addr::from_str("fd00::2").unwrap()));
    }

    #[test]
    fn test_assign_ipv4_only() {
        let _guard = lock_clock(1_000);
        let ipv4 = Ipv4Pool::new(Ipv4Cidr::from_str("10.0.0.0/24").unwrap());
        let mut manager = IpManager::<MockTime>::new(Some(ipv4), None).unwrap();

        let (ipv4, ipv6) = manager.assign(&peer_id(1)).unwrap();
        assert_eq!(ipv4, Some(Ipv4Addr::from_str("10.0.0.1").unwrap()));
        assert_eq!(ipv6, None);
    }

    #[test]
    fn test_assign_without_pools_fails() {
        let _guard = lock_clock(1_000);
        let mut manager = IpManager::<MockTime>::new(None, None).unwrap();
        assert!(manager.assign(&peer_id(1)).is_err());
    }

    #[test]
    fn test_revoke_returns_address_to_pool() {
        let _guard = lock_clock(1_000);
        let mut manager = dual_stack_manager();

        let first = manager.assign(&peer_id(1)).unwrap();
        manager.revoke(&peer_id(1)).unwrap();

        // The recycled address is preferred over a fresh one.
        let second = manager.assign(&peer_id(2)).unwrap();
        assert_eq!(second, first);

        // Revoking an unknown id is a no-op.
        manager.revoke(&peer_id(3)).unwrap();
    }

    #[test]
    fn test_update_refreshes_lease() {
        let _guard = lock_clock(1_000);
        let mut manager = dual_stack_manager();

        let lease = manager.assign(&peer_id(1)).unwrap();
        // Without the update this would expire 300s after assignment.
        advance(200);
        manager.update(&peer_id(1)).unwrap();
        advance(200);
        manager.clean_expired_items().unwrap();

        // Lease still held: same id gets it back, another id gets a fresh one.
        assert_eq!(manager.assign(&peer_id(1)).unwrap(), lease);
        assert_eq!(
            manager.assign(&peer_id(2)).unwrap().0,
            Some(Ipv4Addr::from_str("10.0.0.2").unwrap())
        );
    }

    #[test]
    fn test_clean_expired_items_removes_and_recycles() {
        let _guard = lock_clock(1_000);
        let mut manager = dual_stack_manager();

        let lease = manager.assign(&peer_id(1)).unwrap();
        advance(IP_LEASE_TIMEOUT);
        manager.clean_expired_items().unwrap();
        // Not yet past the boundary.
        assert_eq!(manager.assign(&peer_id(1)).unwrap(), lease);

        advance(1);
        manager.clean_expired_items().unwrap();
        // Lease row deleted and the address returned to the pool.
        let second = manager.assign(&peer_id(2)).unwrap();
        assert_eq!(second, lease);
    }
}
