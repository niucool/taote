    // kauth_unlisten_scope (passthru=true)
    KernelApi("kauth_unlisten_scope", {{"scope", K_POINTER}}, true) = kapi_stub;

    // mbuf_pkthdr_header (passthru=true)
    KernelApi("mbuf_pkthdr_header", {{"mbuf", K_POINTER}}, true) = kapi_stub;

    // mbuf_type (passthru=true)
    KernelApi("mbuf_type", {{"mbuf", K_POINTER}}, true) = kapi_stub;

    // OSAddAtomic (passthru=true)
    KernelApi("OSAddAtomic", {{"amount", K_UINT}, {"address", K_POINTER}}, true) = kapi_stub;

    // mbuf_pkthdr_len (passthru=true)
    KernelApi("mbuf_pkthdr_len", {{"mbuf", K_POINTER}}, true) = kapi_stub;

    // __strlcpy_chk (passthru=true)
    KernelApi("__strlcpy_chk", {{"dst", K_POINTER}, {"src", K_STRING}, {"s", K_SIZE_T}, {"chk_size", K_SIZE_T}}, true) = kapi_stub;

    // OSBitOrAtomic (passthru=true)
    KernelApi("OSBitOrAtomic", {{"mask", K_UINT}, {"address", K_POINTER}}, true) = kapi_stub;

    // OSDecrementAtomic (passthru=true)
    KernelApi("OSDecrementAtomic", {{"address", K_POINTER}}, true) = kapi_stub;

    // kauth_cred_getgid (passthru=true)
    KernelApi("kauth_cred_getgid", {{"cred", K_POINTER}}, true) = kapi_stub;

    // kauth_cred_getuid (passthru=true)
    KernelApi("kauth_cred_getuid", {{"cred", K_POINTER}}, true) = kapi_stub;

    // microtime (passthru=true)
    KernelApi("microtime", {{"tvp", K_POINTER}}, true) = kapi_stub;

    // OSIncrementAtomic (passthru=true)
    KernelApi("OSIncrementAtomic", {{"address", K_POINTER}}, true) = kapi_stub;

    // memset (passthru=true)
    KernelApi("memset", {{"b", K_POINTER}, {"c", K_UINT}, {"len", K_SIZE_T}}, true) = kapi_stub;

    // snprintf (passthru=true)
    KernelApi("snprintf", {{"s", K_POINTER}, {"n", K_SIZE_T}, {"format", K_STRING}}, true) = kapi_stub;

    // __doprnt (passthru=true)
    KernelApi("__doprnt", {{"fmt", K_STRING}, {"argp", K_POINTER}, {"putc", K_POINTER}, {"arg", K_POINTER}, {"radix", K_UINT}, {"is_log", K_UINT}}, true) = kapi_stub;

    // snprintf_func (passthru=true)
    KernelApi("snprintf_func", {{"ch", K_UINT}, {"arg", K_POINTER}}, true) = kapi_stub;

    // __memcpy_chk (passthru=true)
    KernelApi("__memcpy_chk", {{"dst", K_POINTER}, {"src", K_POINTER}, {"s", K_SIZE_T}, {"chk_size", K_SIZE_T}}, true) = kapi_stub;

    // strcmp (passthru=true)
    KernelApi("strcmp", {{"s1", K_STRING}, {"s2", K_STRING}}, true) = kapi_stub;

    // strprefix (passthru=true)
    KernelApi("strprefix", {{"s1", K_STRING}, {"s2", K_STRING}}, true) = kapi_stub;

    // strncmp (passthru=true)
    KernelApi("strncmp", {{"s1", K_STRING}, {"s2", K_STRING}, {"n", K_SIZE_T}}, true) = kapi_stub;

    // strlen (passthru=true)
    KernelApi("strlen", {{"s", K_STRING}}, true) = kapi_stub;

    // inet_ntop (passthru=true)
    KernelApi("inet_ntop", {{"protocol", K_UINT}, {"address", K_POINTER}, {"string", K_POINTER}, {"len", K_SIZE_T}}, true) = kapi_stub;

    // IOLog (passthru=false)
    KernelApi("IOLog", {{"format", K_STRING}}, false) = kapi_stub;

    // printf (passthru=false)
    KernelApi("printf", {{"format", K_STRING}}, false) = kapi_stub;

    // bzero (passthru=true)
    KernelApi("bzero", {{"dst0", K_POINTER}, {"length", K_SIZE_T}}, true) = kapi_stub;

    // sysctlbyname (passthru=true)
    KernelApi("sysctlbyname", {{"p", K_POINTER}, {"uap", K_POINTER}}, true) = kapi_stub;

    // sysctl_handle_string (passthru=true)
    KernelApi("sysctl_handle_string", {{"oidp", K_POINTER}, {"arg1", K_POINTER}, {"arg2", K_UINT}, {"req", K_POINTER}}, true) = kapi_stub;

    // sysctl_old_user (passthru=true)
    KernelApi("sysctl_old_user", {{"req", K_POINTER}, {"p", K_POINTER}, {"l", K_SIZE_T}}, true) = kapi_stub;

    // sysctl_new_user (passthru=true)
    KernelApi("sysctl_new_user", {{"req", K_POINTER}, {"p", K_POINTER}, {"l", K_SIZE_T}}, true) = kapi_stub;

    // sysctl_handle_int (passthru=true)
    KernelApi("sysctl_handle_int", {{"oidp", K_POINTER}, {"arg1", K_POINTER}, {"arg2", K_UINT}, {"req", K_POINTER}}, true) = kapi_stub;

    // sysctl_io_number (passthru=true)
    KernelApi("sysctl_io_number", {{"req", K_POINTER}, {"bigValue", K_ULONGLONG}, {"valueSize", K_SIZE_T}, {"pValue", K_POINTER}, {"changed", K_POINTER}}, true) = kapi_stub;

    // vfs_attr_pack (passthru=true)
    KernelApi("vfs_attr_pack", {{"vp", K_POINTER}, {"uio", K_POINTER}, {"alp", K_POINTER}, {"options", K_ULONGLONG}, {"vap", K_POINTER}, {"fndesc", K_POINTER}, {"ctx", K_POINTER}}, true) = kapi_stub;

    // getattrlist_setupvattr_all (passthru=true)
    KernelApi("getattrlist_setupvattr_all", {{"alp", K_POINTER}, {"vap", K_POINTER}, {"obj_type", K_UINT}, {"fixedsize", K_POINTER}, {"is_64bit", K_UINT}, {"use_fork", K_UINT}}, true) = kapi_stub;

    // vfs_attr_pack_internal (passthru=true)
    KernelApi("vfs_attr_pack_internal", {{"vp", K_POINTER}, {"auio", K_POINTER}, {"alp", K_POINTER}, {"options", K_ULONGLONG}, {"vap", K_POINTER}, {"fndesc", K_POINTER}, {"ctx", K_POINTER}, {"is_bulk", K_UINT}, {"vtype", K_UINT}, {"fixedsize", K_SIZE_T}}, true) = kapi_stub;

    // getattrlist_fixupattrs (passthru=true)
    KernelApi("getattrlist_fixupattrs", {{"asp", K_POINTER}, {"vap", K_POINTER}, {"use_fork", K_UINT}}, true) = kapi_stub;

    // attrlist_pack_string (passthru=true)
    KernelApi("attrlist_pack_string", {{"ab", K_POINTER}, {"source", K_STRING}, {"count", K_SIZE_T}}, true) = kapi_stub;

    // bcopy (passthru=true)
    KernelApi("bcopy", {{"src", K_POINTER}, {"dst", K_POINTER}, {"len", K_SIZE_T}}, true) = kapi_stub;

    // memcpy (passthru=true)
    KernelApi("memcpy", {{"dst", K_POINTER}, {"src", K_POINTER}, {"n", K_SIZE_T}}, true) = kapi_stub;

    // uiomove64 (passthru=true)
    KernelApi("uiomove64", {{"c_cp", K_POINTER}, {"n", K_UINT}, {"uio", K_POINTER}}, true) = kapi_stub;

    // copyout (passthru=true)
    KernelApi("copyout", {{"kernel_addr", K_POINTER}, {"user_addr", K_POINTER}, {"nbytes", K_SIZE_T}}, true) = kapi_stub;

    // uio_update (passthru=true)
    KernelApi("uio_update", {{"a_uio", K_POINTER}, {"a_count", K_SIZE_T}}, true) = kapi_stub;

    // copyin (passthru=true)
    KernelApi("copyin", {{"user_addr", K_POINTER}, {"kernel_addr", K_POINTER}, {"nbytes", K_SIZE_T}}, true) = kapi_stub;

    // __memmove_chk (passthru=true)
    KernelApi("__memmove_chk", {{"dst", K_POINTER}, {"src", K_POINTER}, {"s", K_SIZE_T}, {"chk_size", K_SIZE_T}}, true) = kapi_stub;

    // mbuf_len (passthru=true)
    KernelApi("mbuf_len", {{"mbuf", K_POINTER}}, true) = kapi_stub;

    // mbuf_data (passthru=true)
    KernelApi("mbuf_data", {{"mbuf", K_POINTER}}, true) = kapi_stub;

    // _ZN9IOService5startEPS_ (passthru=true)
    KernelApi("_ZN9IOService5startEPS_", {{"provider", K_POINTER}}, true) = kapi_stub;

    // _ZN9IOService5probeEPS_Pi (passthru=true)
    KernelApi("_ZN9IOService5probeEPS_Pi", {{"provider", K_POINTER}, {"score", K_POINTER}}, true) = kapi_stub;

    // _ZN8OSObjectnwEm (passthru=false)
    KernelApi("_ZN8OSObjectnwEm", {{"size", K_SIZE_T}}, false) = kapi_stub;

    // _ZN9IOServiceC2EPK11OSMetaClass (passthru=false)
    KernelApi("_ZN9IOServiceC2EPK11OSMetaClass", {{"this", K_POINTER}}, false) = kapi_stub;

    // _ZNK11OSMetaClass19instanceConstructedEv (passthru=false)
    KernelApi("_ZNK11OSMetaClass19instanceConstructedEv", {{"this", K_POINTER}}, false) = kapi_stub;

    // _ZN9IOService4initEP12OSDictionary (passthru=false)
    KernelApi("_ZN9IOService4initEP12OSDictionary", {{"this", K_POINTER}, {"option", K_POINTER}}, false) = kapi_stub;

    // _ZN9IOService15registerServiceEj (passthru=false)
    KernelApi("_ZN9IOService15registerServiceEj", {}, false) = kapi_stub;

    // _ZN9IOService6attachEPS_ (passthru=false)
    KernelApi("_ZN9IOService6attachEPS_", {{"provider", K_POINTER}}, false) = kapi_stub;

    // _ZN9IOService6detachEPS_ (passthru=false)
    KernelApi("_ZN9IOService6detachEPS_", {{"provider", K_POINTER}}, false) = kapi_stub;

    // _ZN12IOUserClientC2EPK11OSMetaClass (passthru=false)
    KernelApi("_ZN12IOUserClientC2EPK11OSMetaClass", {{"this", K_POINTER}}, false) = kapi_stub;

    // _ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary (passthru=false)
    KernelApi("_ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary", {{"this", K_POINTER}, {"owningTask", K_UINT}, {"securityID", K_POINTER}, {"type", K_UINT}, {"properties", K_POINTER}}, false) = kapi_stub;

    // OSMalloc_Tagalloc (passthru=false)
    KernelApi("OSMalloc_Tagalloc", {{"str", K_STRING}, {"flags", K_UINT}}, false) = kapi_stub;

    // lck_grp_alloc_init (passthru=false)
    KernelApi("lck_grp_alloc_init", {{"str", K_STRING}, {"attr", K_POINTER}}, false) = kapi_stub;

    // lck_grp_init (passthru=false)
    KernelApi("lck_grp_init", {{"grp", K_POINTER}, {"grp_name", K_STRING}, {"attr", K_POINTER}}, false) = kapi_stub;

    // lck_grp_free (passthru=false)
    KernelApi("lck_grp_free", {{"grp", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_init_ext (passthru=false)
    KernelApi("lck_mtx_init_ext", {{"lck", K_POINTER}, {"lck_ext", K_POINTER}, {"grp", K_POINTER}, {"attr", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_init (passthru=false)
    KernelApi("lck_mtx_init", {{"lck", K_POINTER}, {"grp", K_POINTER}, {"attr", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_alloc_init (passthru=false)
    KernelApi("lck_mtx_alloc_init", {{"grp", K_POINTER}, {"attr", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_lock (passthru=false)
    KernelApi("lck_mtx_lock", {{"lock", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_unlock (passthru=false)
    KernelApi("lck_mtx_unlock", {{"lock", K_POINTER}}, false) = kapi_stub;

    // proc_list_lock (passthru=false)
    KernelApi("proc_list_lock", {}, false) = kapi_stub;

    // proc_list_unlock (passthru=false)
    KernelApi("proc_list_unlock", {}, false) = kapi_stub;

    // OSMalloc (passthru=false)
    KernelApi("OSMalloc", {{"size", K_SIZE_T}, {"tag", K_POINTER}}, false) = kapi_stub;

    // OSFree (passthru=false)
    KernelApi("OSFree", {{"addr", K_POINTER}, {"size", K_UINT}, {"tag", K_POINTER}}, false) = kapi_stub;

    // kalloc_canblock (passthru=false)
    KernelApi("kalloc_canblock", {{"psize", K_POINTER}, {"canblock", K_BOOL}, {"site", K_POINTER}}, false) = kapi_stub;

    // kfree (passthru=false)
    KernelApi("kfree", {{"data", K_POINTER}, {"size", K_SIZE_T}}, false) = kapi_stub;

    // _MALLOC (passthru=false)
    KernelApi("_MALLOC", {{"size", K_SIZE_T}, {"type", K_UINT}, {"flags", K_UINT}}, false) = kapi_stub;

    // _FREE (passthru=false)
    KernelApi("_FREE", {{"addr", K_POINTER}, {"type", K_UINT}}, false) = kapi_stub;

    // lck_rw_lock_exclusive (passthru=false)
    KernelApi("lck_rw_lock_exclusive", {{"lock", K_POINTER}}, false) = kapi_stub;

    // lck_rw_unlock_exclusive (passthru=false)
    KernelApi("lck_rw_unlock_exclusive", {{"lock", K_POINTER}}, false) = kapi_stub;

    // lck_rw_done (passthru=false)
    KernelApi("lck_rw_done", {{"lock", K_POINTER}}, false) = kapi_stub;

    // OSCompareAndSwap (passthru=false)
    KernelApi("OSCompareAndSwap", {{"oldValue", K_POINTER}, {"newValue", K_POINTER}, {"address", K_POINTER}}, false) = kapi_stub;

    // lck_mtx_assert (passthru=false)
    KernelApi("lck_mtx_assert", {{"lock", K_POINTER}, {"type", K_UINT}}, false) = kapi_stub;

    // panic (passthru=true)
    KernelApi("panic", {{"format", K_STRING}}, true) = kapi_stub;

    // clock_get_calendar_microtime (passthru=false)
    KernelApi("clock_get_calendar_microtime", {{"tv_sec", K_POINTER}, {"tv_usec", K_POINTER}}) = syscall_kapi_clock_get_calendar_microtime;

    // read_random (passthru=false)
    KernelApi("read_random", {{"buf", K_POINTER}, {"size", K_UINT}}) = syscall_kapi_read_random;

    // read_erandom (passthru=false)
    KernelApi("read_erandom", {{"buf", K_POINTER}, {"size", K_UINT}}) = syscall_kapi_read_erandom;

    // copyio (passthru=false)
    KernelApi("copyio", {{"copy_type", K_UINT}, {"user_addr", K_POINTER}, {"kernel_addr", K_POINTER}, {"nbytes", K_SIZE_T}, {"lencopied", K_POINTER}, {"use_kernel_map", K_UINT}}, false) = kapi_stub;

    // kfree_addr (passthru=false)
    KernelApi("kfree_addr", {{"addr", K_POINTER}}, false) = kapi_stub;

    // fuulong (passthru=false)
    KernelApi("fuulong", {{"addr", K_POINTER}}) = syscall_kapi_fuulong;

    // suulong (passthru=false)
    KernelApi("suulong", {{"addr", K_POINTER}, {"uword", K_ULONGLONG}}) = syscall_kapi_suulong;

    // proc_selfpid (passthru=false)
    KernelApi("proc_selfpid", {}) = syscall_kapi_proc_selfpid;

    // proc_name (passthru=false)
    KernelApi("proc_name", {{"pid", K_UINT}, {"buf", K_POINTER}, {"size", K_UINT}}, false) = kapi_stub;

    // proc_selfppid (passthru=false)
    KernelApi("proc_selfppid", {}) = syscall_kapi_proc_selfppid;

    // proc_find (passthru=false)
    KernelApi("proc_find", {{"pid", K_UINT}}, false) = kapi_stub;

    // vfs_context_proc (passthru=false)
    KernelApi("vfs_context_proc", {{"ctx", K_POINTER}}) = syscall_kapi_vfs_context_proc;

    // kauth_cred_setuidgid (passthru=false)
    KernelApi("kauth_cred_setuidgid", {{"cred", K_POINTER}, {"uid", K_UINT}, {"gid", K_UINT}}, false) = kapi_stub;

    // vn_getpath (passthru=false)
    KernelApi("vn_getpath", {{"vp", K_POINTER}, {"pathbuf", K_POINTER}, {"len", K_POINTER}}, false) = kapi_stub;

    // kernel_thread_start (passthru=false)
    KernelApi("kernel_thread_start", {{"continuation", K_POINTER}, {"params", K_POINTER}, {"new_thread", K_POINTER}}) = syscall_kapi_kernel_thread_start;

    // kauth_getuid (passthru=false)
    KernelApi("kauth_getuid", {}, false) = kapi_stub;

    // kauth_getgid (passthru=false)
    KernelApi("kauth_getgid", {}, false) = kapi_stub;

    // msleep (passthru=false)
    KernelApi("msleep", {}) = syscall_kapi_msleep;

    // sock_getsockname (passthru=false)
    KernelApi("sock_getsockname", {{"so", K_POINTER}, {"sockname", K_POINTER}, {"socknamelen", K_UINT}}, false) = kapi_stub;

    // KUNCExecute (passthru=false)
    KernelApi("KUNCExecute", {{"cmd", K_STRING}}, false) = kapi_stub;

    // sysctl_register_oid (passthru=false)
    KernelApi("sysctl_register_oid", {{"oidp", K_POINTER}}, false) = kapi_stub;

    // sysctl_unregister_oid (passthru=false)
    KernelApi("sysctl_unregister_oid", {{"oidp", K_POINTER}}, false) = kapi_stub;

    // sysctl_root (passthru=false)
    KernelApi("sysctl_root", {{"from_kernel", K_BOOL}, {"string_is_canonical", K_BOOL}, {"namestring", K_POINTER}, {"namestringlen", K_SIZE_T}, {"name", K_POINTER}, {"namelen", K_UINT}, {"req", K_POINTER}}, false) = kapi_stub;

    // ctl_register (passthru=false)
    KernelApi("ctl_register", {{"userctl", K_POINTER}, {"ctlref", K_POINTER}}, false) = kapi_stub;

    // ctl_deregister (passthru=false)
    KernelApi("ctl_deregister", {{"ctlref", K_POINTER}}, false) = kapi_stub;

    // sflt_register (passthru=false)
    KernelApi("sflt_register", {{"filter", K_POINTER}, {"domain", K_UINT}, {"type", K_UINT}, {"protocol", K_UINT}}, false) = kapi_stub;

    // sflt_unregister (passthru=false)
    KernelApi("sflt_unregister", {{"handle", K_UINT}}, false) = kapi_stub;

    // mac_policy_register (passthru=false)
    KernelApi("mac_policy_register", {{"mpc", K_POINTER}, {"handlep", K_POINTER}, {"xd", K_POINTER}}, false) = kapi_stub;

    // mac_policy_unregister (passthru=false)
    KernelApi("mac_policy_unregister", {{"handle", K_POINTER}}, false) = kapi_stub;

    // kauth_listen_scope (passthru=false)
    KernelApi("kauth_listen_scope", {{"_identifier", K_POINTER}, {"_callback", K_POINTER}, {"_idata", K_POINTER}}, false) = kapi_stub;

    // ipf_addv4 (passthru=false)
    KernelApi("ipf_addv4", {{"filter", K_POINTER}, {"filter_ref", K_POINTER}}, false) = kapi_stub;

    // getattrlistbulk (passthru=false)
    KernelApi("getattrlistbulk", {{"p", K_POINTER}, {"getattrlistbulk_args", K_POINTER}, {"retval", K_POINTER}}, false) = kapi_stub;
