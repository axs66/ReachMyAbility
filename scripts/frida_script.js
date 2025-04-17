// frida_script.js

// 目标类名（修改为你实际目标类名）
var targetClass = ObjC.classes.TargetClass;

// 目标方法（修改为你实际目标方法名）
var targetMethod = targetClass["- targetMethod:"];

// Hook 目标方法
Interceptor.attach(targetMethod.implementation, {
    onEnter: function(args) {
        // 在方法调用时，打印入参
        console.log("调用 targetMethod: 参数 " + args[0].toInt32());
    },
    onLeave: function(retval) {
        // 在方法返回时，打印返回值
        console.log("targetMethod 返回值: " + retval);
    }
});
