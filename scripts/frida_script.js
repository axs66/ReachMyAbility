// scripts/frida_script.js
if (ObjC.available) {
    const classes = ObjC.enumerateLoadedClassesSync();
    for (let className in classes) {
        try {
            const methods = ObjC.classes[className].$ownMethods;
            methods.forEach(method => {
                const impl = ObjC.classes[className][method];
                Interceptor.attach(impl.implementation, {
                    onEnter: function (args) {
                        console.log('[*] ' + className + ' -> ' + method);
                    }
                });
            });
        } catch (e) {}
    }
} else {
    console.log("Objective-C runtime is not available.");
}
