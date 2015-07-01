

#[macro_export]
macro_rules! read_be {
    ($buf:expr, $offset:expr, $ty:ty) => ({
        (*($buf.as_ptr().offset($offset as isize) as *const $ty)).to_be()
    });
}

#[macro_export]
macro_rules! write_be {
    ($buf:expr, $offset:expr, $v:expr, $size:expr) => ({
        let ptr = (::std::mem::transmute::<_, [u8; $size]>($v.to_be())).as_ptr();
        ::std::ptr::copy_nonoverlapping(ptr, $buf.as_mut_ptr().offset($offset as isize), $size);
    })
}
