pub struct ResolverConfig<'a> {
    pub hosts: &'a str,
}

pub struct Resolver {
    pub todo: bool,
}

impl Resolver {
    pub fn new() -> Resolver {
        Resolver{
            todo: true,
        }
    }
}
