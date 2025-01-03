// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::absolute_paths)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::zero_repeat_side_effects)]
#[warn(single_use_lifetimes)]
mod imp {
    #[allow(unused_imports)]
    use super::*;
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;
    use libbpf_rs::AsRawLibbpf as _;
    use libbpf_rs::MapCore as _;
    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder
            .name("xdp_blocker_bpf")
            .map("block_list", false)
            .map("xdp_stats_map", false)
            .map("xdp_bloc.rodata", false)
            .prog("xdp_test");
        builder.build()
    }
    pub struct OpenXdpBlockerMaps<'obj> {
        pub block_list: libbpf_rs::OpenMapMut<'obj>,
        pub xdp_stats_map: libbpf_rs::OpenMapMut<'obj>,
        pub rodata: libbpf_rs::OpenMapMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> OpenXdpBlockerMaps<'obj> {
        #[allow(unused_variables)]
        unsafe fn new(
            config: &libbpf_rs::__internal_skel::ObjectSkeletonConfig<'_>,
            object: &mut libbpf_rs::OpenObject,
        ) -> libbpf_rs::Result<Self> {
            let mut block_list = None;
            let mut xdp_stats_map = None;
            let mut rodata = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::OpenObject, &'obj mut libbpf_rs::OpenObject>(
                    object,
                )
            };
            #[allow(clippy::never_loop)]
            for map in object.maps_mut() {
                let name = map.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "map has invalid name",
                    ))
                })?;
                #[allow(clippy::match_single_binding)]
                match name {
                    "block_list" => block_list = Some(map),
                    "xdp_stats_map" => xdp_stats_map = Some(map),
                    "xdp_bloc.rodata" => rodata = Some(map),
                    _ => panic!("encountered unexpected map: `{name}`"),
                }
            }

            let slf = Self {
                block_list: block_list.expect("map `block_list` not present"),
                xdp_stats_map: xdp_stats_map.expect("map `xdp_stats_map` not present"),
                rodata: rodata.expect("map `rodata` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct XdpBlockerMaps<'obj> {
        pub block_list: libbpf_rs::MapMut<'obj>,
        pub xdp_stats_map: libbpf_rs::MapMut<'obj>,
        pub rodata: libbpf_rs::MapMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> XdpBlockerMaps<'obj> {
        #[allow(unused_variables)]
        unsafe fn new(
            config: &libbpf_rs::__internal_skel::ObjectSkeletonConfig<'_>,
            object: &mut libbpf_rs::Object,
        ) -> libbpf_rs::Result<Self> {
            let mut block_list = None;
            let mut xdp_stats_map = None;
            let mut rodata = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::Object, &'obj mut libbpf_rs::Object>(object)
            };
            #[allow(clippy::never_loop)]
            for map in object.maps_mut() {
                let name = map.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "map has invalid name",
                    ))
                })?;
                #[allow(clippy::match_single_binding)]
                match name {
                    "block_list" => block_list = Some(map),
                    "xdp_stats_map" => xdp_stats_map = Some(map),
                    "xdp_bloc.rodata" => rodata = Some(map),
                    _ => panic!("encountered unexpected map: `{name}`"),
                }
            }

            let slf = Self {
                block_list: block_list.expect("map `block_list` not present"),
                xdp_stats_map: xdp_stats_map.expect("map `xdp_stats_map` not present"),
                rodata: rodata.expect("map `rodata` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct OpenXdpBlockerProgs<'obj> {
        pub xdp_test: libbpf_rs::OpenProgramMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> OpenXdpBlockerProgs<'obj> {
        unsafe fn new(object: &mut libbpf_rs::OpenObject) -> libbpf_rs::Result<Self> {
            let mut xdp_test = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::OpenObject, &'obj mut libbpf_rs::OpenObject>(
                    object,
                )
            };
            for prog in object.progs_mut() {
                let name = prog.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "prog has invalid name",
                    ))
                })?;
                match name {
                    "xdp_test" => xdp_test = Some(prog),
                    _ => panic!("encountered unexpected prog: `{name}`"),
                }
            }

            let slf = Self {
                xdp_test: xdp_test.expect("prog `xdp_test` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct XdpBlockerProgs<'obj> {
        pub xdp_test: libbpf_rs::ProgramMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> XdpBlockerProgs<'obj> {
        #[allow(unused_variables)]
        fn new(open_progs: OpenXdpBlockerProgs<'obj>) -> Self {
            Self {
                xdp_test: unsafe {
                    libbpf_rs::ProgramMut::new_mut(open_progs.xdp_test.as_libbpf_object().as_mut())
                },
                _phantom: std::marker::PhantomData,
            }
        }
    }
    struct OwnedRef<'obj, O> {
        object: Option<&'obj mut std::mem::MaybeUninit<O>>,
    }

    impl<'obj, O> OwnedRef<'obj, O> {
        /// # Safety
        /// The object has to be initialized.
        unsafe fn new(object: &'obj mut std::mem::MaybeUninit<O>) -> Self {
            Self {
                object: Some(object),
            }
        }

        fn as_ref(&self) -> &O {
            // SAFETY: As per the contract during construction, the
            //         object has to be initialized.
            unsafe { self.object.as_ref().unwrap().assume_init_ref() }
        }

        fn as_mut(&mut self) -> &mut O {
            // SAFETY: As per the contract during construction, the
            //         object has to be initialized.
            unsafe { self.object.as_mut().unwrap().assume_init_mut() }
        }

        fn take(mut self) -> &'obj mut std::mem::MaybeUninit<O> {
            self.object.take().unwrap()
        }
    }

    impl<O> Drop for OwnedRef<'_, O> {
        fn drop(&mut self) {
            if let Some(object) = &mut self.object {
                unsafe { object.assume_init_drop() }
            }
        }
    }

    #[derive(Default)]
    pub struct XdpBlockerSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'obj> XdpBlockerSkelBuilder {
        fn open_opts_impl(
            self,
            open_opts: *const libbpf_sys::bpf_object_open_opts,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenXdpBlockerSkel<'obj>> {
            let skel_config = build_skel_config()?;
            let skel_ptr = skel_config.as_libbpf_object();

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_ptr.as_ptr(), open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            // SAFETY: `skel_ptr` points to a valid object after the
            //         open call.
            let obj_ptr = unsafe { *skel_ptr.as_ref().obj };
            // SANITY: `bpf_object__open_skeleton` should have
            //         allocated the object.
            let obj_ptr = std::ptr::NonNull::new(obj_ptr).unwrap();
            // SAFETY: `obj_ptr` points to an opened object after
            //         skeleton open.
            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(obj_ptr) };
            let _obj = object.write(obj);
            // SAFETY: We just wrote initialized data to `object`.
            let mut obj_ref = unsafe { OwnedRef::new(object) };

            #[allow(unused_mut)]
            let mut skel = OpenXdpBlockerSkel {
                maps: unsafe { OpenXdpBlockerMaps::new(&skel_config, obj_ref.as_mut())? },
                progs: unsafe { OpenXdpBlockerProgs::new(obj_ref.as_mut())? },
                obj: obj_ref,
                // SAFETY: Our `struct_ops` type contains only pointers,
                //         which are allowed to be NULL.
                // TODO: Generate and use a `Default` representation
                //       instead, to cut down on unsafe code.
                struct_ops: unsafe { std::mem::zeroed() },
                skel_config,
            };

            Ok(skel)
        }
    }

    impl<'obj> SkelBuilder<'obj> for XdpBlockerSkelBuilder {
        type Output = OpenXdpBlockerSkel<'obj>;
        fn open(
            self,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenXdpBlockerSkel<'obj>> {
            self.open_opts_impl(std::ptr::null(), object)
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenXdpBlockerSkel<'obj>> {
            self.open_opts_impl(&open_opts, object)
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    #[derive(Debug, Clone)]
    #[repr(C)]
    pub struct StructOps {}

    impl StructOps {}
    pub mod types {
        #[allow(unused_imports)]
        use super::*;
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct ipv4_lpm_key {
            pub prefixlen: u32,
            pub data: u32,
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct __anon_1 {
            pub r#type: *mut [i32; 11],
            pub key: *mut ipv4_lpm_key,
            pub value: *mut u32,
            pub map_flags: *mut [i32; 1],
            pub max_entries: *mut [i32; 255],
        }
        impl Default for __anon_1 {
            fn default() -> Self {
                Self {
                    r#type: std::ptr::null_mut(),
                    key: std::ptr::null_mut(),
                    value: std::ptr::null_mut(),
                    map_flags: std::ptr::null_mut(),
                    max_entries: std::ptr::null_mut(),
                }
            }
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct __anon_2 {
            pub r#type: *mut [i32; 6],
            pub key_size: *mut [i32; 4],
            pub value_size: *mut [i32; 16],
            pub max_entries: *mut [i32; 5],
            pub pinning: *mut [i32; 1],
        }
        impl Default for __anon_2 {
            fn default() -> Self {
                Self {
                    r#type: std::ptr::null_mut(),
                    key_size: std::ptr::null_mut(),
                    value_size: std::ptr::null_mut(),
                    max_entries: std::ptr::null_mut(),
                    pinning: std::ptr::null_mut(),
                }
            }
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct xdp_md {
            pub data: u32,
            pub data_end: u32,
            pub data_meta: u32,
            pub ingress_ifindex: u32,
            pub rx_queue_index: u32,
            pub egress_ifindex: u32,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct ethhdr {
            pub h_dest: [u8; 6],
            pub h_source: [u8; 6],
            pub h_proto: u16,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct iphdr {
            pub __pad_0: [u8; 1],
            pub tos: u8,
            pub tot_len: u16,
            pub id: u16,
            pub frag_off: u16,
            pub ttl: u8,
            pub protocol: u8,
            pub check: u16,
            pub __anon_3: __anon_3,
        }
        #[derive(Copy, Clone)]
        #[repr(C)]
        pub union __anon_3 {
            pub __anon_4: __anon_4,
            pub addrs: __anon_4,
        }
        impl std::fmt::Debug for __anon_3 {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "(???)")
            }
        }
        impl Default for __anon_3 {
            fn default() -> Self {
                Self {
                    __anon_4: __anon_4::default(),
                }
            }
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct __anon_4 {
            pub saddr: u32,
            pub daddr: u32,
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct maps {
            pub block_list: __anon_1,
            pub xdp_stats_map: __anon_2,
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct rodata {}
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct license {
            pub _license: [i8; 4],
        }
    }
    pub struct OpenXdpBlockerSkel<'obj> {
        obj: OwnedRef<'obj, libbpf_rs::OpenObject>,
        pub maps: OpenXdpBlockerMaps<'obj>,
        pub progs: OpenXdpBlockerProgs<'obj>,
        pub struct_ops: StructOps,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
    }

    impl<'obj> OpenSkel<'obj> for OpenXdpBlockerSkel<'obj> {
        type Output = XdpBlockerSkel<'obj>;
        fn load(self) -> libbpf_rs::Result<XdpBlockerSkel<'obj>> {
            let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();

            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(skel_ptr) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj_ref = self.obj.take();
            let open_obj = std::mem::replace(obj_ref, std::mem::MaybeUninit::uninit());
            // SAFETY: `open_obj` is guaranteed to be properly
            //         initialized as it came from an `OwnedRef`.
            let obj_ptr = unsafe { open_obj.assume_init().take_ptr() };
            // SAFETY: `obj_ptr` points to a loaded object after
            //         skeleton load.
            let obj = unsafe { libbpf_rs::Object::from_ptr(obj_ptr) };
            // SAFETY: `OpenObject` and `Object` are guaranteed to
            //         have the same memory layout.
            let obj_ref = unsafe {
                std::mem::transmute::<
                    &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
                    &'obj mut std::mem::MaybeUninit<libbpf_rs::Object>,
                >(obj_ref)
            };
            let _obj = obj_ref.write(obj);
            // SAFETY: We just wrote initialized data to `obj_ref`.
            let mut obj_ref = unsafe { OwnedRef::new(obj_ref) };

            Ok(XdpBlockerSkel {
                maps: unsafe { XdpBlockerMaps::new(&self.skel_config, obj_ref.as_mut())? },
                progs: XdpBlockerProgs::new(self.progs),
                obj: obj_ref,
                struct_ops: self.struct_ops,
                skel_config: self.skel_config,
                links: XdpBlockerLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            self.obj.as_ref()
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            self.obj.as_mut()
        }
    }
    #[derive(Default)]
    pub struct XdpBlockerLinks {
        pub xdp_test: Option<libbpf_rs::Link>,
    }
    pub struct XdpBlockerSkel<'obj> {
        obj: OwnedRef<'obj, libbpf_rs::Object>,
        pub maps: XdpBlockerMaps<'obj>,
        pub progs: XdpBlockerProgs<'obj>,
        struct_ops: StructOps,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
        pub links: XdpBlockerLinks,
    }

    unsafe impl Send for XdpBlockerSkel<'_> {}
    unsafe impl Sync for XdpBlockerSkel<'_> {}

    impl<'obj> Skel<'obj> for XdpBlockerSkel<'obj> {
        fn object(&self) -> &libbpf_rs::Object {
            self.obj.as_ref()
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            self.obj.as_mut()
        }
        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(skel_ptr) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            self.links = XdpBlockerLinks {
                xdp_test: core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                    .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }),
            };

            Ok(())
        }
    }
    impl XdpBlockerSkel<'_> {
        pub fn struct_ops_raw(&self) -> *const StructOps {
            &self.struct_ops
        }

        pub fn struct_ops(&self) -> &StructOps {
            &self.struct_ops
        }
    }
    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 12, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 46, 116, 101, 120, 116, 0, 120, 100, 112, 0, 46, 109, 97, 112, 115, 0, 46, 114, 111,
        100, 97, 116, 97, 0, 108, 105, 99, 101, 110, 115, 101, 0, 120, 100, 112, 95, 98, 108, 111,
        99, 107, 101, 114, 46, 98, 112, 102, 46, 99, 0, 76, 66, 66, 49, 95, 53, 0, 120, 100, 112,
        95, 116, 101, 115, 116, 46, 95, 95, 95, 95, 102, 109, 116, 0, 76, 66, 66, 49, 95, 55, 0,
        108, 111, 111, 107, 117, 112, 95, 101, 108, 101, 109, 0, 98, 108, 111, 99, 107, 95, 108,
        105, 115, 116, 0, 120, 100, 112, 95, 116, 101, 115, 116, 0, 120, 100, 112, 95, 115, 116,
        97, 116, 115, 95, 109, 97, 112, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 101,
        108, 46, 116, 101, 120, 116, 0, 46, 114, 101, 108, 120, 100, 112, 0, 46, 66, 84, 70, 0, 46,
        66, 84, 70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 67, 0, 0, 0, 0,
        0, 4, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 0, 91, 0, 0, 0, 0, 0, 4, 0, 152, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 98, 0, 0, 0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 110, 0, 0,
        0, 17, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 121, 0, 0, 0, 18, 0, 4, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 168, 1, 0, 0, 0, 0, 0, 0, 130, 0, 0, 0, 17, 0, 5, 0, 40, 0, 0, 0,
        0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 144, 0, 0, 0, 17, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
        0, 0, 0, 0, 0, 0, 0, 99, 26, 252, 255, 0, 0, 0, 0, 183, 1, 0, 0, 32, 0, 0, 0, 99, 26, 248,
        255, 0, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 248, 255, 255, 255, 24, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 1, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0,
        191, 22, 0, 0, 0, 0, 0, 0, 183, 7, 0, 0, 0, 0, 0, 0, 97, 98, 4, 0, 0, 0, 0, 0, 97, 99, 0,
        0, 0, 0, 0, 0, 191, 49, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 14, 0, 0, 0, 183, 4, 0, 0, 0, 0, 0,
        0, 45, 33, 24, 0, 0, 0, 0, 0, 105, 53, 12, 0, 0, 0, 0, 0, 183, 4, 0, 0, 2, 0, 0, 0, 85, 5,
        21, 0, 8, 0, 0, 0, 7, 3, 0, 0, 34, 0, 0, 0, 183, 4, 0, 0, 0, 0, 0, 0, 45, 35, 18, 0, 0, 0,
        0, 0, 97, 17, 12, 0, 0, 0, 0, 0, 99, 26, 252, 255, 0, 0, 0, 0, 183, 1, 0, 0, 32, 0, 0, 0,
        99, 26, 248, 255, 0, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 248, 255, 255, 255,
        24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 1, 0, 0, 0, 183, 4, 0, 0, 2,
        0, 0, 0, 21, 0, 7, 0, 0, 0, 0, 0, 97, 3, 0, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 24,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 59, 0, 0, 0, 133, 0, 0, 0, 6, 0,
        0, 0, 183, 4, 0, 0, 1, 0, 0, 0, 99, 74, 244, 255, 0, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0,
        7, 2, 0, 0, 244, 255, 255, 255, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0,
        0, 1, 0, 0, 0, 21, 0, 12, 0, 0, 0, 0, 0, 121, 1, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 1, 0, 0, 0,
        123, 16, 0, 0, 0, 0, 0, 0, 97, 97, 0, 0, 0, 0, 0, 0, 97, 98, 4, 0, 0, 0, 0, 0, 31, 18, 0,
        0, 0, 0, 0, 0, 103, 2, 0, 0, 32, 0, 0, 0, 119, 2, 0, 0, 32, 0, 0, 0, 121, 1, 8, 0, 0, 0, 0,
        0, 15, 33, 0, 0, 0, 0, 0, 0, 123, 16, 8, 0, 0, 0, 0, 0, 97, 167, 244, 255, 0, 0, 0, 0, 191,
        112, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 120, 100, 112, 95, 98, 108, 111, 99, 107, 101, 114, 58, 32, 102, 111,
        117, 110, 100, 32, 37, 112, 73, 52, 32, 105, 110, 32, 116, 104, 101, 32, 98, 108, 111, 99,
        107, 32, 108, 105, 115, 116, 44, 32, 100, 114, 111, 112, 112, 105, 110, 103, 32, 112, 97,
        99, 107, 101, 116, 0, 71, 80, 76, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0,
        160, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 216, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7,
        0, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 11, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0,
        0, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 38, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4,
        0, 0, 0, 11, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 6, 0, 0, 0, 25, 0, 0, 0, 2, 0, 0, 4, 8, 0, 0, 0, 38, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
        48, 0, 0, 0, 7, 0, 0, 0, 32, 0, 0, 0, 53, 0, 0, 0, 0, 0, 0, 8, 8, 0, 0, 0, 59, 0, 0, 0, 0,
        0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 2, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0,
        0, 255, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 4, 40, 0, 0, 0, 72, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        77, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 81, 0, 0, 0, 9, 0, 0, 0, 128, 0, 0, 0, 87, 0, 0, 0,
        10, 0, 0, 0, 192, 0, 0, 0, 97, 0, 0, 0, 12, 0, 0, 0, 0, 1, 0, 0, 109, 0, 0, 0, 0, 0, 0, 14,
        14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
        0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 19, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 21, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 2, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 5, 0,
        0, 0, 0, 0, 0, 0, 5, 0, 0, 4, 40, 0, 0, 0, 72, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0,
        0, 18, 0, 0, 0, 64, 0, 0, 0, 129, 0, 0, 0, 20, 0, 0, 0, 128, 0, 0, 0, 97, 0, 0, 0, 22, 0,
        0, 0, 192, 0, 0, 0, 140, 0, 0, 0, 10, 0, 0, 0, 0, 1, 0, 0, 148, 0, 0, 0, 0, 0, 0, 14, 24,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 27, 0, 0, 0, 162, 0, 0, 0, 7, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 169, 0, 0, 0, 1, 0, 0, 12, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 30, 0, 0, 0, 181, 0, 0, 0, 6, 0, 0, 4, 24, 0, 0, 0, 48, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
        188, 0, 0, 0, 7, 0, 0, 0, 32, 0, 0, 0, 197, 0, 0, 0, 7, 0, 0, 0, 64, 0, 0, 0, 207, 0, 0, 0,
        7, 0, 0, 0, 96, 0, 0, 0, 223, 0, 0, 0, 7, 0, 0, 0, 128, 0, 0, 0, 238, 0, 0, 0, 7, 0, 0, 0,
        160, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 7, 0, 0, 0, 253, 0, 0, 0, 29, 0, 0, 0, 1, 1, 0, 0,
        1, 0, 0, 12, 31, 0, 0, 0, 10, 1, 0, 0, 3, 0, 0, 4, 14, 0, 0, 0, 17, 1, 0, 0, 35, 0, 0, 0,
        0, 0, 0, 0, 24, 1, 0, 0, 35, 0, 0, 0, 48, 0, 0, 0, 33, 1, 0, 0, 36, 0, 0, 0, 96, 0, 0, 0,
        41, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 34, 0,
        0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 55, 1, 0, 0, 0, 0, 0, 8, 37, 0, 0, 0, 62, 1, 0, 0, 0, 0, 0,
        8, 38, 0, 0, 0, 68, 1, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 16, 0, 0, 0, 83, 1, 0, 0, 10, 0, 0,
        132, 20, 0, 0, 0, 89, 1, 0, 0, 40, 0, 0, 0, 0, 0, 0, 4, 93, 1, 0, 0, 40, 0, 0, 0, 4, 0, 0,
        4, 101, 1, 0, 0, 40, 0, 0, 0, 8, 0, 0, 0, 105, 1, 0, 0, 36, 0, 0, 0, 16, 0, 0, 0, 113, 1,
        0, 0, 36, 0, 0, 0, 32, 0, 0, 0, 116, 1, 0, 0, 36, 0, 0, 0, 48, 0, 0, 0, 125, 1, 0, 0, 40,
        0, 0, 0, 64, 0, 0, 0, 129, 1, 0, 0, 40, 0, 0, 0, 72, 0, 0, 0, 138, 1, 0, 0, 41, 0, 0, 0,
        80, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 96, 0, 0, 0, 144, 1, 0, 0, 0, 0, 0, 8, 34, 0, 0, 0,
        149, 1, 0, 0, 0, 0, 0, 8, 37, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 5, 8, 0, 0, 0, 0, 0, 0, 0, 43,
        0, 0, 0, 0, 0, 0, 0, 157, 1, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 4, 8, 0,
        0, 0, 163, 1, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 169, 1, 0, 0, 44, 0, 0, 0, 32, 0, 0, 0, 175,
        1, 0, 0, 0, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 46, 0, 0, 0, 182, 1, 0, 0, 0, 0,
        0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 45, 0, 0, 0, 4, 0, 0, 0,
        59, 0, 0, 0, 187, 1, 0, 0, 0, 0, 0, 14, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 46, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 204, 1, 0, 0, 0, 0, 0, 14, 49, 0, 0, 0, 1, 0,
        0, 0, 10, 5, 0, 0, 2, 0, 0, 15, 80, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 25, 0,
        0, 0, 40, 0, 0, 0, 40, 0, 0, 0, 16, 5, 0, 0, 1, 0, 0, 15, 59, 0, 0, 0, 48, 0, 0, 0, 0, 0,
        0, 0, 59, 0, 0, 0, 24, 5, 0, 0, 1, 0, 0, 15, 4, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
        0, 0, 105, 110, 116, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69,
        95, 95, 0, 105, 112, 118, 52, 95, 108, 112, 109, 95, 107, 101, 121, 0, 112, 114, 101, 102,
        105, 120, 108, 101, 110, 0, 100, 97, 116, 97, 0, 95, 95, 117, 51, 50, 0, 117, 110, 115,
        105, 103, 110, 101, 100, 32, 105, 110, 116, 0, 116, 121, 112, 101, 0, 107, 101, 121, 0,
        118, 97, 108, 117, 101, 0, 109, 97, 112, 95, 102, 108, 97, 103, 115, 0, 109, 97, 120, 95,
        101, 110, 116, 114, 105, 101, 115, 0, 98, 108, 111, 99, 107, 95, 108, 105, 115, 116, 0,
        107, 101, 121, 95, 115, 105, 122, 101, 0, 118, 97, 108, 117, 101, 95, 115, 105, 122, 101,
        0, 112, 105, 110, 110, 105, 110, 103, 0, 120, 100, 112, 95, 115, 116, 97, 116, 115, 95,
        109, 97, 112, 0, 105, 112, 97, 100, 100, 114, 0, 108, 111, 111, 107, 117, 112, 95, 101,
        108, 101, 109, 0, 120, 100, 112, 95, 109, 100, 0, 100, 97, 116, 97, 95, 101, 110, 100, 0,
        100, 97, 116, 97, 95, 109, 101, 116, 97, 0, 105, 110, 103, 114, 101, 115, 115, 95, 105,
        102, 105, 110, 100, 101, 120, 0, 114, 120, 95, 113, 117, 101, 117, 101, 95, 105, 110, 100,
        101, 120, 0, 101, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 120,
        100, 112, 0, 120, 100, 112, 95, 116, 101, 115, 116, 0, 101, 116, 104, 104, 100, 114, 0,
        104, 95, 100, 101, 115, 116, 0, 104, 95, 115, 111, 117, 114, 99, 101, 0, 104, 95, 112, 114,
        111, 116, 111, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 99, 104, 97, 114, 0, 95, 95,
        98, 101, 49, 54, 0, 95, 95, 117, 49, 54, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32,
        115, 104, 111, 114, 116, 0, 105, 112, 104, 100, 114, 0, 105, 104, 108, 0, 118, 101, 114,
        115, 105, 111, 110, 0, 116, 111, 115, 0, 116, 111, 116, 95, 108, 101, 110, 0, 105, 100, 0,
        102, 114, 97, 103, 95, 111, 102, 102, 0, 116, 116, 108, 0, 112, 114, 111, 116, 111, 99,
        111, 108, 0, 99, 104, 101, 99, 107, 0, 95, 95, 117, 56, 0, 95, 95, 115, 117, 109, 49, 54,
        0, 97, 100, 100, 114, 115, 0, 115, 97, 100, 100, 114, 0, 100, 97, 100, 100, 114, 0, 95, 95,
        98, 101, 51, 50, 0, 99, 104, 97, 114, 0, 120, 100, 112, 95, 116, 101, 115, 116, 46, 95, 95,
        95, 95, 102, 109, 116, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0, 47, 104, 111, 109, 101,
        47, 98, 120, 102, 102, 111, 117, 114, 47, 115, 114, 99, 47, 120, 100, 112, 45, 115, 101,
        110, 116, 105, 110, 101, 108, 47, 115, 114, 99, 47, 98, 112, 102, 47, 120, 100, 112, 95,
        98, 108, 111, 99, 107, 101, 114, 46, 98, 112, 102, 46, 99, 0, 32, 32, 115, 116, 114, 117,
        99, 116, 32, 105, 112, 118, 52, 95, 108, 112, 109, 95, 107, 101, 121, 32, 107, 101, 121,
        32, 61, 32, 123, 0, 32, 32, 114, 101, 116, 117, 114, 110, 32, 98, 112, 102, 95, 109, 97,
        112, 95, 108, 111, 111, 107, 117, 112, 95, 101, 108, 101, 109, 40, 38, 98, 108, 111, 99,
        107, 95, 108, 105, 115, 116, 44, 32, 38, 107, 101, 121, 41, 59, 0, 95, 95, 117, 51, 50, 32,
        120, 100, 112, 95, 116, 101, 115, 116, 40, 115, 116, 114, 117, 99, 116, 32, 120, 100, 112,
        95, 109, 100, 32, 42, 120, 100, 112, 41, 32, 123, 0, 32, 32, 118, 111, 105, 100, 32, 42,
        100, 97, 116, 97, 95, 101, 110, 100, 32, 61, 32, 40, 118, 111, 105, 100, 42, 41, 40, 108,
        111, 110, 103, 41, 120, 100, 112, 45, 62, 100, 97, 116, 97, 95, 101, 110, 100, 59, 0, 32,
        32, 118, 111, 105, 100, 32, 42, 100, 97, 116, 97, 32, 61, 32, 40, 118, 111, 105, 100, 42,
        41, 40, 108, 111, 110, 103, 41, 120, 100, 112, 45, 62, 100, 97, 116, 97, 59, 0, 32, 32,
        105, 102, 32, 40, 100, 97, 116, 97, 32, 43, 32, 111, 102, 102, 32, 62, 32, 100, 97, 116,
        97, 95, 101, 110, 100, 41, 32, 123, 0, 32, 32, 101, 116, 104, 95, 112, 114, 111, 116, 111,
        32, 61, 32, 101, 116, 104, 45, 62, 104, 95, 112, 114, 111, 116, 111, 59, 0, 32, 32, 105,
        102, 32, 40, 101, 116, 104, 95, 112, 114, 111, 116, 111, 32, 33, 61, 32, 66, 69, 95, 69,
        84, 72, 95, 80, 95, 73, 80, 41, 32, 123, 0, 32, 32, 105, 102, 32, 40, 105, 112, 104, 32,
        43, 32, 49, 32, 62, 32, 100, 97, 116, 97, 95, 101, 110, 100, 41, 32, 123, 0, 32, 32, 118,
        97, 108, 32, 61, 32, 108, 111, 111, 107, 117, 112, 95, 101, 108, 101, 109, 40, 105, 112,
        104, 45, 62, 115, 97, 100, 100, 114, 41, 59, 0, 32, 32, 105, 102, 32, 40, 118, 97, 108, 41,
        32, 123, 0, 32, 32, 32, 32, 98, 112, 102, 95, 112, 114, 105, 110, 116, 107, 40, 34, 120,
        100, 112, 95, 98, 108, 111, 99, 107, 101, 114, 58, 32, 102, 111, 117, 110, 100, 32, 37,
        112, 73, 52, 32, 105, 110, 32, 116, 104, 101, 32, 98, 108, 111, 99, 107, 32, 108, 105, 115,
        116, 44, 32, 100, 114, 111, 112, 112, 105, 110, 103, 32, 112, 97, 99, 107, 101, 116, 34,
        44, 32, 98, 112, 102, 95, 110, 116, 111, 104, 108, 40, 42, 118, 97, 108, 41, 41, 59, 0, 47,
        104, 111, 109, 101, 47, 98, 120, 102, 102, 111, 117, 114, 47, 115, 114, 99, 47, 120, 100,
        112, 45, 115, 101, 110, 116, 105, 110, 101, 108, 47, 115, 114, 99, 47, 98, 112, 102, 47,
        120, 100, 112, 95, 98, 108, 111, 99, 107, 101, 114, 95, 100, 101, 102, 115, 46, 104, 0, 32,
        32, 115, 116, 114, 117, 99, 116, 32, 100, 97, 116, 97, 114, 101, 99, 32, 42, 114, 101, 99,
        32, 61, 32, 98, 112, 102, 95, 109, 97, 112, 95, 108, 111, 111, 107, 117, 112, 95, 101, 108,
        101, 109, 40, 38, 120, 100, 112, 95, 115, 116, 97, 116, 115, 95, 109, 97, 112, 44, 32, 38,
        97, 99, 116, 105, 111, 110, 41, 59, 0, 32, 32, 105, 102, 32, 40, 33, 114, 101, 99, 41, 32,
        123, 0, 32, 32, 114, 101, 99, 45, 62, 114, 120, 95, 112, 97, 99, 107, 101, 116, 115, 32,
        43, 61, 32, 49, 59, 0, 32, 32, 114, 101, 99, 45, 62, 114, 120, 95, 98, 121, 116, 101, 115,
        32, 43, 61, 32, 40, 120, 100, 112, 45, 62, 100, 97, 116, 97, 95, 101, 110, 100, 32, 45, 32,
        120, 100, 112, 45, 62, 100, 97, 116, 97, 41, 59, 0, 32, 32, 114, 101, 116, 117, 114, 110,
        32, 97, 99, 116, 105, 111, 110, 59, 0, 32, 32, 32, 32, 114, 101, 116, 117, 114, 110, 32,
        120, 100, 112, 95, 115, 116, 97, 116, 115, 95, 114, 101, 99, 111, 114, 100, 95, 97, 99,
        116, 105, 111, 110, 40, 120, 100, 112, 44, 32, 97, 99, 116, 105, 111, 110, 41, 59, 0, 48,
        58, 49, 0, 48, 58, 48, 0, 48, 58, 50, 0, 48, 58, 57, 58, 48, 58, 48, 0, 46, 109, 97, 112,
        115, 0, 46, 114, 111, 100, 97, 116, 97, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 116,
        101, 120, 116, 0, 0, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 36, 0, 0, 0,
        244, 1, 0, 0, 24, 2, 0, 0, 108, 0, 0, 0, 8, 0, 0, 0, 32, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        28, 0, 0, 0, 253, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 16, 0, 0, 0, 32, 5, 0, 0,
        4, 0, 0, 0, 0, 0, 0, 0, 213, 1, 0, 0, 14, 2, 0, 0, 29, 28, 0, 0, 32, 0, 0, 0, 213, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 213, 1, 0, 0, 44, 2, 0, 0, 10, 48, 0, 0, 64, 0, 0, 0,
        213, 1, 0, 0, 44, 2, 0, 0, 3, 48, 0, 0, 253, 0, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 213, 1, 0,
        0, 93, 2, 0, 0, 0, 64, 0, 0, 16, 0, 0, 0, 213, 1, 0, 0, 130, 2, 0, 0, 38, 72, 0, 0, 24, 0,
        0, 0, 213, 1, 0, 0, 177, 2, 0, 0, 34, 68, 0, 0, 32, 0, 0, 0, 213, 1, 0, 0, 216, 2, 0, 0,
        12, 116, 0, 0, 56, 0, 0, 0, 213, 1, 0, 0, 216, 2, 0, 0, 7, 116, 0, 0, 64, 0, 0, 0, 213, 1,
        0, 0, 247, 2, 0, 0, 20, 136, 0, 0, 80, 0, 0, 0, 213, 1, 0, 0, 19, 3, 0, 0, 7, 140, 0, 0,
        88, 0, 0, 0, 213, 1, 0, 0, 53, 3, 0, 0, 11, 164, 0, 0, 104, 0, 0, 0, 213, 1, 0, 0, 53, 3,
        0, 0, 7, 164, 0, 0, 112, 0, 0, 0, 213, 1, 0, 0, 81, 3, 0, 0, 26, 184, 0, 0, 120, 0, 0, 0,
        213, 1, 0, 0, 14, 2, 0, 0, 29, 28, 0, 0, 152, 0, 0, 0, 213, 1, 0, 0, 81, 3, 0, 0, 26, 184,
        0, 0, 160, 0, 0, 0, 213, 1, 0, 0, 44, 2, 0, 0, 10, 48, 0, 0, 192, 0, 0, 0, 213, 1, 0, 0,
        114, 3, 0, 0, 7, 188, 0, 0, 200, 0, 0, 0, 213, 1, 0, 0, 127, 3, 0, 0, 5, 192, 0, 0, 16, 1,
        0, 0, 213, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 1, 0, 0, 222, 3, 0, 0, 24, 4, 0, 0, 25,
        228, 0, 0, 48, 1, 0, 0, 222, 3, 0, 0, 94, 4, 0, 0, 7, 232, 0, 0, 56, 1, 0, 0, 222, 3, 0, 0,
        108, 4, 0, 0, 19, 248, 0, 0, 80, 1, 0, 0, 222, 3, 0, 0, 132, 4, 0, 0, 42, 252, 0, 0, 88, 1,
        0, 0, 222, 3, 0, 0, 132, 4, 0, 0, 26, 252, 0, 0, 96, 1, 0, 0, 222, 3, 0, 0, 132, 4, 0, 0,
        35, 252, 0, 0, 104, 1, 0, 0, 222, 3, 0, 0, 132, 4, 0, 0, 20, 252, 0, 0, 120, 1, 0, 0, 222,
        3, 0, 0, 132, 4, 0, 0, 17, 252, 0, 0, 144, 1, 0, 0, 222, 3, 0, 0, 180, 4, 0, 0, 10, 4, 1,
        0, 152, 1, 0, 0, 213, 1, 0, 0, 197, 4, 0, 0, 5, 216, 0, 0, 16, 0, 0, 0, 253, 0, 0, 0, 6, 0,
        0, 0, 16, 0, 0, 0, 30, 0, 0, 0, 246, 4, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 30, 0, 0, 0, 250, 4,
        0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 33, 0, 0, 0, 254, 4, 0, 0, 0, 0, 0, 0, 112, 0, 0, 0, 39, 0,
        0, 0, 2, 5, 0, 0, 0, 0, 0, 0, 80, 1, 0, 0, 30, 0, 0, 0, 250, 4, 0, 0, 0, 0, 0, 0, 88, 1, 0,
        0, 30, 0, 0, 0, 246, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
        32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 185, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0,
        0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 56,
        1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0,
        0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 2, 0, 0, 0,
        0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 23, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        128, 2, 0, 0, 0, 0, 0, 0, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 40, 4, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 4, 0, 0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 1, 0, 0, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 179, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 153, 0, 0, 0, 9, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 184, 4, 0, 0, 0, 0, 0, 0, 16, 0, 0,
        0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0,
        163, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 4, 0, 0, 0,
        0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0,
        0, 0, 0, 0, 0, 171, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        248, 4, 0, 0, 0, 0, 0, 0, 62, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 176, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 56, 15, 0, 0, 0, 0, 0, 0, 164, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
