use std::{ffi::{c_int, c_void}, fs::OpenOptions, os::windows::io::AsRawHandle, sync::Mutex, thread::sleep, time::Duration};

use anyhow::Context;
use jnihook_rs::{jnihook_attach, jnihook_init, jnihook_shutdown, HookedMethodId};

use windows::{core::s, Win32::Foundation::HINSTANCE};
use winapi::um::{consoleapi::AllocConsole, libloaderapi::{FreeLibraryAndExitThread, GetModuleHandleA, GetProcAddress}, processenv::SetStdHandle, winbase::STD_OUTPUT_HANDLE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use winapi::um::wincon::FreeConsole;

type GetCreatedJavaVMs = extern "system" fn(*mut *mut c_void, c_int, *mut c_int) -> c_int;

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

fn get_jni_get_created_jvms() -> Option<GetCreatedJavaVMs> {
    let jvm_module = unsafe { GetModuleHandleA(s!("jvm.dll").as_ptr() as *const i8) };
    if jvm_module.is_null() {
        return None;
    }

    let jvm_proc_address = unsafe { GetProcAddress(jvm_module, s!("JNI_GetCreatedJavaVMs").as_ptr() as *const i8) };
    if jvm_proc_address.is_null() {
        return None;
    }
    
    let get_created_jvm = unsafe { std::mem::transmute(jvm_proc_address) };
    
    Some(get_created_jvm)
}

unsafe fn start() -> anyhow::Result<()> {
    AllocConsole();
    
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .open("CONOUT$")?;
    SetStdHandle(
        STD_OUTPUT_HANDLE,
        file.as_raw_handle() as *mut winapi::ctypes::c_void
    );

    println!("library loaded");
    
    let mut jvm_ciunt = 0;

    let mut jvm_raw = Vec::<*mut c_void>::with_capacity(1);

    if get_jni_get_created_jvms().context("get_jni_get_created_jvms")?(
        jvm_raw.as_mut_ptr(),
        1,
        &mut jvm_ciunt
    ) != jvmti::native::jvmti_native::JVMTI_ERROR_NONE as i32 {
        return Err(anyhow::anyhow!("failed to get jvm"));
    }

    jvm_raw.set_len(jvm_ciunt as usize);

    println!("jvm: {:?}", jvm_raw.len());

    let jvm = jni::JavaVM::from_raw(*jvm_raw.first().context("jvm is empty")? as *mut jni::sys::JavaVM)?;
    let mut env = jvm.attach_current_thread()?;

    let target_class = env.find_class("bew")?;
    println!("class: {:?}", target_class.as_raw());

    let target_method = env.get_method_id(target_class, "t_", "()V")?;
    println!("method: {:?}", target_method.into_raw());

    jnihook_init(jvm.get_java_vm_pointer())?;

    let (original_class, original_method) = jnihook_attach(target_method, hk_player_on_update as *mut c_void)?;

    assert!(matches!(original_method, HookedMethodId::NonStatic(_)));

    ORIGINAL_CLASS.lock().unwrap().replace(original_class);
    if let HookedMethodId::NonStatic(method) = original_method {
        ORIGINAL_METHOD.lock().unwrap().replace(method);
    }

    println!("hooked");

    sleep(Duration::from_secs(10));

    println!("unhooking");

    jnihook_shutdown()?;

    jvm.detach_current_thread();

    Ok(())
}

#[no_mangle]
extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| unsafe {
            if let anyhow::Result::Err(err) = start() {
                println!("error: {:?}", err);
            }
            
            println!("freeing console");
            println!("you may now close this window");

            FreeConsole();

            let module = GetModuleHandleA(s!("test.dll").as_ptr() as *const i8);
            FreeLibraryAndExitThread(module, 0);
        });
    }
    true
}