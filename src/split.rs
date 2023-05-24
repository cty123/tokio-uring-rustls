use crate::TlsStream;

use rustls::{ConnectionCommon, SideData};
use tokio_uring::BufResult;

use std::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    rc::Rc,
};

#[derive(Debug)]
pub struct ReadHalf<C> {
    pub(crate) inner: Rc<UnsafeCell<TlsStream<C>>>,
}

#[derive(Debug)]
pub struct WriteHalf<C> {
    pub(crate) inner: Rc<UnsafeCell<TlsStream<C>>>,
}

impl<C, SD: SideData + 'static> ReadHalf<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub async fn read<B: tokio_uring::buf::IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        let inner = unsafe { &mut *self.inner.get() };
        return inner.read(buf).await;
    }
}

impl<C, SD: SideData + 'static> WriteHalf<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub async fn write<B: tokio_uring::buf::IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let inner = unsafe { &mut *self.inner.get() };
        return inner.write(buf).await;
    }

    pub async fn write_all<B: tokio_uring::buf::IoBuf>(&mut self, buf: B) -> BufResult<(), B> {
        let inner = unsafe { &mut *self.inner.get() };
        return inner.write_all(buf).await;
    }
}

pub fn split<C: DerefMut + Deref<Target = ConnectionCommon<SD>>, SD: SideData + 'static>(
    stream: TlsStream<C>,
) -> (ReadHalf<C>, WriteHalf<C>) {
    let shared = Rc::new(UnsafeCell::new(stream));
    (
        ReadHalf {
            inner: shared.clone(),
        },
        WriteHalf { inner: shared },
    )
}
