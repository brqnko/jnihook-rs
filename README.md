# jnihook-rs

jnihook-rs is a Rust implementation of [JNIHook](https://github.com/rdbo/jnihook)

## License
This project is licensed under the `GNU AGPL-3.0`. No later version is allowed.

Read the file `LICENSE` for more information.

## Example

```rs
static ORIGINAL_CLASS: Mutex<Option<jni::objects::JClass>> = Mutex::new(None);
static ORIGINAL_METHOD: Mutex<Option<jni::objects::JMethodID>> = Mutex::new(None);

unsafe extern "system" fn hk_player_on_update(
    jni: jvmti::native::JNIEnvPtr,
    obj: jvmti::native::JavaObject,
) {
    println!("player on update hook called");

    (**jni).CallNonvirtualVoidMethod.unwrap()(
        jni,
        obj,
        ORIGINAL_CLASS.lock().unwrap().as_ref().unwrap().as_raw() as *mut jvmti::native::jvmti_native::Struct__jobject,
        ORIGINAL_METHOD.lock().unwrap().as_ref().unwrap().into_raw() as *mut jvmti::native::jvmti_native::Struct__jmethodID
    );
}

unsafe fn start(jvm: &jni::JavaVM, env: &mut jni::JNIEnv) -> anyhow::Result<()> {
    let target_class = env.find_class("bew")?;
    let target_method = env.get_method_id(target_class, "t_", "()V")?;

    jnihook_init(jvm.get_java_vm_pointer())?;

    let (original_class, original_method) = jnihook_attach(target_method, hk_player_on_update as *mut c_void)?;

    ORIGINAL_CLASS.lock().unwrap().replace(original_class);
    if let HookedMethodId::NonStatic(method) = original_method {
        ORIGINAL_METHOD.lock().unwrap().replace(method);
    }

    sleep(Duration::from_secs(10));

    jnihook_shutdown()?;

    Ok(())
}
```

## Creadit

Thanks rdbo for making the JNIHook
