use std::marker::PhantomData;

use sea_orm::{entity::EntityTrait, DatabaseConnection, DbErr, PrimaryKeyTrait};

use super::Store;

#[derive(Clone)]
pub struct SqlDb<E: EntityTrait> {
    db_conn: DatabaseConnection,
    _entity: PhantomData<E>,
}

impl<E: EntityTrait> SqlDb<E>
where
    <<E as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType: From<String>,
{
    pub fn new(db_conn: DatabaseConnection) -> Self {
        Self { db_conn, _entity: PhantomData }
    }
}

#[async_trait::async_trait]
impl<E: EntityTrait> Store for SqlDb<E>
where
    <<E as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType: From<String>,
{
    type Error = DbErr;
    async fn verify_api_key(&self, api_key: String) -> Result<(), Self::Error> {
        E::find_by_id(api_key)
            .one(&self.db_conn)
            .await?
            .ok_or_else(|| DbErr::RecordNotFound("API key not found".into()))?;

        Ok(())
    }
}
