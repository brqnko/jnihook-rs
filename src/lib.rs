use std::{
    alloc::{alloc, Layout}, collections::HashMap, ffi::c_void, ptr::{null, null_mut}, sync::{LazyLock, Mutex}
};

use anyhow::Context;
use jvmti::environment::jvmti::JVMTI;

struct JniHook {
    jvm: jni::JavaVM,
    jvmti: jvmti::environment::jvmti::JVMTIEnvironment,
    jvmti_raw: jvmti::native::JVMTIEnvPtr,
}

unsafe impl Send for JniHook {}

#[derive(Clone, Debug)]
struct MethodInfo {
    name: String,
    signature: String,
    access_flags: i32,
}

#[derive(Clone, Debug)]
struct HookInfo {
    method_info: MethodInfo,
}

unsafe impl Send for HookInfo {}

#[derive(Clone, Debug)]
pub enum HookedMethodId {
    NonStatic(jni::objects::JMethodID),
    Static(jni::objects::JStaticMethodID),
}

#[derive(Debug)]
pub enum HookResult {
    NonStatic(jni::objects::JClass<'static>, jni::objects::JMethodID),
    Static(jni::objects::JClass<'static>, jni::objects::JStaticMethodID),
}

static JNI_HOOK: Mutex<Option<JniHook>> = Mutex::new(None);
static CLASS_FILE_CACHE: LazyLock<Mutex<HashMap<String, jvmti::bytecode::Classfile>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static HOOKS: LazyLock<Mutex<HashMap<String, Vec<HookInfo>>>> = LazyLock::new(||Mutex::new(HashMap::new()));
static ORIGINAL_CLASSES: LazyLock<Mutex<HashMap<String, jni::objects::JClass<'static>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static ORIGINAL_CLASS_FILE_CACHE: LazyLock<Mutex<HashMap<String, Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

unsafe fn get_method_info(jvmti: jvmti::native::JVMTIEnvPtr, method: &jvmti::method::MethodId) -> anyhow::Result<MethodInfo> {
    let mut method_name = null_mut();
    let method_ptr = &mut method_name;

    let mut signature: jvmti::native::MutString = null_mut();
    let signature_ptr = &mut signature;

    let mut generic_sig: jvmti::native::MutString = null_mut();
    let generic_sig_ptr = &mut generic_sig;

    (**jvmti).GetMethodName.context("failed to get method name")?(jvmti, method.native_id, method_ptr, signature_ptr, generic_sig_ptr);

    Ok(MethodInfo {
        name: jvmti::util::stringify(*method_ptr),
        signature: jvmti::util::stringify(*signature_ptr),
        access_flags: *signature_ptr as i32,
    })
}

unsafe fn get_class_name(env: &mut jni::JNIEnv<'_>, class: &jvmti::class::ClassId) -> anyhow::Result<String> {
    let klass = env.find_class("java/lang/Class")?;
    let get_name = env.get_method_id(klass, "getName", "()Ljava/lang/String;")?;
    let name = env.call_method_unchecked(
        jni::objects::JObject::from_raw(class.native_id as *mut jni::sys::_jobject),
        get_name,
        jni::signature::ReturnType::Object, &[]
    )?.l()?;

    Ok(env.get_string(&jni::objects::JString::from_raw(name.into_raw()))?.to_str()?.replace(".", "/"))
}

fn class_file_load_hook(event: jvmti::runtime::ClassFileLoadEvent) -> Option<Vec<u8>> {
    let mut class_file_cache = CLASS_FILE_CACHE.lock().unwrap();
    let hooks = HOOKS.lock().unwrap();

    let hooks = hooks.get(&event.class_name)?;

    if hooks.is_empty() {
        return None;
    }

    if class_file_cache.contains_key(&event.class_name) {
        return None;
    }

    class_file_cache.insert(event.class_name, event.class);
    
    None
}

/// # Safety
/// 
/// This function is unsafe because it's dealing with raw pointers.
pub unsafe fn jnihook_init(jvm: *mut jni::sys::JavaVM) -> anyhow::Result<()> {
    let jvmti_raw = alloc(Layout::new::<jvmti::native::jvmti_native::jvmtiEnv>()) as *mut *mut c_void;
    if (**jvm).GetEnv.context("Failed to get GetEnv")?(jvm, jvmti_raw, jvmti::native::jvmti_native::JVMTI_VERSION_1_2 as i32)
        != jvmti::native::jvmti_native::JVMTI_ERROR_NONE as i32 {
        return Err(anyhow::anyhow!("Failed to get JVMTI environment"));
    }

    let mut jvmti = jvmti::environment::jvmti::JVMTIEnvironment::new(*jvmti_raw as jvmti::native::JVMTIEnvPtr);

    let mut capabilities = jvmti.get_capabilities();
	capabilities.can_redefine_classes = true;
	capabilities.can_redefine_any_class = true;
	capabilities.can_retransform_classes = true;
	capabilities.can_retransform_any_class = true;

    let Result::Ok(_) = jvmti.add_capabilities(&capabilities) else {
        return Err(anyhow::anyhow!("Failed to add capabilities"));
    };

    let callbacks = jvmti::event::EventCallbacks {
        class_file_load_hook: Some(class_file_load_hook),
        ..Default::default()
    };
    jvmti.set_event_callbacks(callbacks);

    let jvm = jni::JavaVM::from_raw(jvm).context("Failed to get JavaVM")?;

    JNI_HOOK.lock().unwrap().replace(JniHook {
        jvm,
        jvmti,
        jvmti_raw: *jvmti_raw as jvmti::native::JVMTIEnvPtr
    });

    Ok(())
}

/// # Safety
/// 
/// This function is unsafe because it's dealing with raw pointers.
pub unsafe fn jnihook_attach(
    method: jni::objects::JMethodID,
    native_hook_method: *const c_void,
) -> anyhow::Result<(jni::objects::JClass<'static>, HookedMethodId)> {
    let method = jvmti::method::MethodId {
        native_id: method.into_raw() as jvmti::native::JavaMethod
    };
    let mut jni_hook = JNI_HOOK.lock().unwrap();
    let Some(jni_hook) = jni_hook.as_mut() else {
        return Err(anyhow::anyhow!("JNI hook not initialized"));
    };

    let mut env = jni_hook.jvm.get_env()?;

    let Result::Ok(class) = jni_hook.jvmti.get_method_declaring_class(&method) else {
        return Err(anyhow::anyhow!("Failed to get class"));
    };

    let class_name = get_class_name(&mut env, &class)?;
    let method_info = get_method_info(jni_hook.jvmti_raw, &method)?;
    let hook_info = HookInfo {
        method_info: method_info.clone(),
    };

    if !CLASS_FILE_CACHE.lock().unwrap().contains_key(&class_name) {
        jni_hook.jvmti.set_event_notification_mode(jvmti::event::VMEvent::ClassFileLoadHook, true);

        HOOKS.lock().unwrap().entry(class_name.clone()).or_default().push(hook_info.clone());

        (**jni_hook.jvmti_raw).RetransformClasses.context("Failed to get RetransformClasses")?(jni_hook.jvmti_raw, 1, &class.native_id);
        
        HOOKS.lock().unwrap().get_mut(&class_name).unwrap().pop();
        
        jni_hook.jvmti.set_event_notification_mode(jvmti::event::VMEvent::ClassFileLoadHook, false);

        if !CLASS_FILE_CACHE.lock().unwrap().contains_key(&class_name) {
            return Err(anyhow::anyhow!("Failed to load class file"));
        }
    }

    if !ORIGINAL_CLASSES.lock().unwrap().contains_key(&class_name) {
        let mut class_file_cache = CLASS_FILE_CACHE.lock().unwrap();

        let mut class_data = Vec::<u8>::new();
        let mut writer = jvmti::bytecode::writer::ClassWriter::new(&mut class_data);
        writer.write_class(class_file_cache.get(&class_name).unwrap())?;
        ORIGINAL_CLASS_FILE_CACHE.lock().unwrap().insert(class_name.clone(), class_data.clone());
        let mut cursor = std::io::Cursor::new(class_data);
        let mut class_file = jvmti::bytecode::reader::ClassReader::read_class(&mut cursor).context("Failed to read class")?;

        let class_copy_name = format!("{}_{}", class_name, uuid::Uuid::new_v4().to_string().replace("-", "_"));
        let class_copy_source_name = format!("{}.java", class_copy_name.split("/").last().unwrap());

        let mut replaces = Vec::new();
        for attr in class_file_cache[&class_name].attributes.iter() {
            let jvmti::bytecode::classfile::Attribute::SourceFile(idx) = attr else {
                continue;
            };

            replaces.push(jvmti::bytecode::classfile::ConstantPoolIndex::new(idx.idx));
        }

        let mut replaces2 = Vec::new();
        for replace in replaces {
            let attr_name = jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(&replace, &class_file_cache.get(&class_name).unwrap().constant_pool);
            if attr_name == "SourceFile" {
                continue;
            }

            replaces2.push((replace.idx, jvmti::bytecode::classfile::Constant::Utf8(class_copy_source_name.clone().into())));
        }

        for replace in replaces2 {
            class_file_cache.get_mut(&class_name).unwrap().constant_pool.constants[replace.0] = replace.1;
        }

        let mut replaces = Vec::new();
        for cpi in class_file.constant_pool.constants.iter() {
            let jvmti::bytecode::classfile::Constant::Class(idx) = cpi else {
                continue;
            };
            replaces.push(jvmti::bytecode::classfile::ConstantPoolIndex::new(idx.idx));
        }

        let mut replaces2 = Vec::new();
        replaces.iter().for_each(|idx| {
            if class_name == jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(idx, &class_file.constant_pool) {
                replaces2.push((idx.idx, jvmti::bytecode::classfile::Constant::Utf8(class_copy_name.clone().into())));
            }
        });

        for replace in replaces2 {
            class_file.constant_pool.constants[replace.0] = replace.1;
        }

        let mut replaces = Vec::new();
        for cfi in class_file_cache.get(&class_name).unwrap().constant_pool.constants.iter() {
            if let jvmti::bytecode::classfile::Constant::NameAndType { name_index, descriptor_index } = cfi {
                replaces.push((jvmti::bytecode::classfile::ConstantPoolIndex::new(name_index.idx), jvmti::bytecode::classfile::ConstantPoolIndex::new(descriptor_index.idx)));
            }
        }

        let mut replaces2 = Vec::new();
        for replace in replaces.iter() {
            let desc = jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(&replace.1, &class_file_cache.get(&class_name).unwrap().constant_pool);

            let class_desc = format!("L{};", class_name);
            let class_copy_desc = format!("L{};", class_copy_name);
            if desc.contains(&class_desc) {
                let new_desc = desc.replace(&class_desc, &class_copy_desc);

                replaces2.push((jvmti::bytecode::classfile::ConstantPoolIndex::new(replace.1.idx), jvmti::bytecode::classfile::Constant::Utf8(new_desc.into())));
            }
        }

        for replace in replaces2 {
            class_file_cache.get_mut(&class_name).unwrap().constant_pool.constants[replace.0.idx] = replace.1;
        }

        let mut replaces = Vec::new();
        for method in class_file_cache.get(&class_name).unwrap().methods.iter() {
            replaces.push((
                jvmti::bytecode::classfile::ConstantPoolIndex::new(method.name_index.idx), 
                jvmti::bytecode::classfile::ConstantPoolIndex::new(method.descriptor_index.idx)
            ));
        }

        let mut replaces2 = Vec::new();
        for idx in replaces.iter() {
            let descriptor = jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(&idx.1, &class_file_cache.get(&class_name).unwrap().constant_pool);

            let class_desc = format!("L{};", class_name);
            let class_copy_desc = format!("L{};", class_copy_name);
            if descriptor.contains(&class_desc) {
                let new_desc = descriptor.replace(&class_desc, &class_copy_desc);

                replaces2.push((jvmti::bytecode::classfile::ConstantPoolIndex::new(idx.1.idx), jvmti::bytecode::classfile::Constant::Utf8(new_desc.into())));
            }
        }

        for replace in replaces2 {
            class_file_cache.get_mut(&class_name).unwrap().constant_pool.constants[replace.0.idx] = replace.1;
        }
        
        let mut class_data = Vec::<u8>::new();
        let mut writer = jvmti::bytecode::writer::ClassWriter::new(&mut class_data);
        writer.write_class(&class_file)?;

        let mut class_loader = alloc(Layout::new::<jni::sys::jobject>()) as *mut jvmti::native::jvmti_native::Struct__jobject;
        (**jni_hook.jvmti_raw).GetClassLoader.context("Failed to get GetClassLoader")?(jni_hook.jvmti_raw, class.native_id, &mut class_loader);

        let class_copy = (**jni_hook.jvm.get_env()?.get_raw()).DefineClass.context("Failed to get DefineClass")?
            (jni_hook.jvm.get_env()?.get_raw(), null(), class_loader as *mut jni::sys::_jobject, class_data.as_ptr() as *const jni::sys::jbyte, class_data.len() as i32);

        ORIGINAL_CLASSES.lock().unwrap().insert(class_name.clone(), jni::objects::JClass::from_raw(class_copy));
    }

    let original_classes = ORIGINAL_CLASSES.lock().unwrap();

    if !original_classes.contains_key(&class_name) {
        return Err(anyhow::anyhow!("Failed to create class copy"));
    }

    HOOKS.lock().unwrap().entry(class_name.clone()).or_default().push(hook_info);
    reapply_class(jni_hook, &class, &class_name, CLASS_FILE_CACHE.lock().unwrap().get_mut(&class_name).unwrap())?;

    let native_method = jni::NativeMethod {
        name: method_info.name.clone().into(),
        sig: method_info.signature.clone().into(),
        fn_ptr: native_hook_method as *mut c_void,
    };
    let mut env = jni_hook.jvm.get_env()?;

    env.register_native_methods(jni::objects::JClass::from_raw(class.native_id as *mut jni::sys::_jobject), &[native_method])?;

    let class = jni::objects::JClass::from_raw(original_classes.get(&class_name).unwrap().as_raw());

    if (method_info.access_flags & jvmti::bytecode::classfile::MethodAccessFlags::Static as i32) == jvmti::bytecode::classfile::MethodAccessFlags::Static as i32 {
        let method_id = env.get_static_method_id(original_classes.get(&class_name).unwrap(), method_info.name, method_info.signature)?;
        
        Ok((class, HookedMethodId::Static(method_id)))
    } else {
        let method_id = env.get_method_id(original_classes.get(&class_name).unwrap(), method_info.name, method_info.signature)?;
    
        Ok((class, HookedMethodId::NonStatic(method_id)))
    }
}

unsafe fn reapply_class(
    jni_hook: &mut JniHook,
    class: &jvmti::class::ClassId,
    class_name: &str,
    class_file: &mut jvmti::bytecode::Classfile,
) -> anyhow::Result<()> {
    let mut replaces = Vec::new();
    for method in class_file.methods.iter() {
        replaces.push((
            jvmti::bytecode::classfile::ConstantPoolIndex::new(method.name_index.idx),
            jvmti::bytecode::classfile::ConstantPoolIndex::new(method.descriptor_index.idx)
        ));
    }

    for (i, idx) in replaces.iter().enumerate() {
        let name = jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(&idx.0, &class_file.constant_pool);
        let desc = jvmti::bytecode::printer::ClassfilePrinter::resolve_utf8(&idx.1, &class_file.constant_pool);

        if !HOOKS.lock().unwrap().get(class_name).unwrap().iter().any(|hook| hook.method_info.name == name && hook.method_info.signature == desc) {
            continue;
        }
        
        class_file.methods.get_mut(i).unwrap().access_flags.flags |= jvmti::bytecode::classfile::MethodAccessFlags::Native as u16;

        let mut should_remove = Vec::new();
        for (j, attr) in class_file.methods.get_mut(i).unwrap().attributes.iter().enumerate() {
            if matches!(attr, jvmti::bytecode::classfile::Attribute::Code { max_stack: _, max_locals: _, code: _, exception_table: _, attributes: _ }) {
                should_remove.push(j);
            }
        }

        for j in should_remove.iter() {
            class_file.methods.get_mut(i).unwrap().attributes.remove(*j);
        }
    }

    let mut class_data = Vec::<u8>::new();
    let mut writer = jvmti::bytecode::writer::ClassWriter::new(&mut class_data);
    writer.write_class(class_file)?;

    let class_definition = jvmti::native::jvmti_native::jvmtiClassDefinition {
        klass: class.native_id,
        class_bytes: class_data.as_ptr(),
        class_byte_count: class_data.len() as i32,
    };
    (**jni_hook.jvmti_raw).RedefineClasses.context("Failed to get RedefineClasses")?(jni_hook.jvmti_raw, 1, &class_definition);
    
    anyhow::Result::Ok(())
}

/// # Safety
/// 
/// This function is unsafe because it's dealing with raw pointers.
pub unsafe fn jnihook_shutdown() -> anyhow::Result<()> {
    let mut jni_hook = JNI_HOOK.lock().unwrap();
    let Some(jni_hook) = jni_hook.as_mut() else {
        return Err(anyhow::anyhow!("JNI hook not initialized"));
    };
    
    let original_class_file_cache = ORIGINAL_CLASS_FILE_CACHE.lock().unwrap();
    let mut class_file_cache = CLASS_FILE_CACHE.lock().unwrap();
    
    class_file_cache.iter_mut().for_each(|(k, _)| {
        HOOKS.lock().unwrap().get_mut(k).unwrap().clear();

        let class = **jni_hook.jvm.get_env().unwrap().find_class(k).context("Failed to find class").unwrap();

        if class.is_null() {
            return;
        }

        let Some(class_data) = original_class_file_cache.get(k) else {
            return;
        };

        let class_definition = jvmti::native::jvmti_native::jvmtiClassDefinition {
            klass: class as jvmti::native::JavaClass,
            class_bytes: class_data.as_ptr(),
            class_byte_count: class_data.len() as i32,
        };
        (**jni_hook.jvmti_raw).RedefineClasses.context("Failed to get RedefineClasses").unwrap()(jni_hook.jvmti_raw, 1, &class_definition);
    });

    jni_hook.jvmti.set_event_callbacks(jvmti::event::EventCallbacks::default());

    jni_hook.jvmti.set_event_notification_mode(jvmti::event::VMEvent::ClassFileLoadHook, false);

    Ok(())
}