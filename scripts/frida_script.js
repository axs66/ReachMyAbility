// 定义全局变量以便后续调用
var targetProcess = null;
var targetModule = null;

// 监听函数，打印函数调用栈
function traceFunctionCalls(funcName) {
    var targetFunc = Module.findExportByName(targetModule, funcName);
    if (targetFunc !== null) {
        console.log('[*] Hooking ' + funcName);
        Interceptor.attach(targetFunc, {
            onEnter: function(args) {
                console.log('Called ' + funcName + ' with arguments: ' + args);
            },
            onLeave: function(retval) {
                console.log('Function ' + funcName + ' returned: ' + retval);
            }
        });
    } else {
        console.log('[!] ' + funcName + ' not found');
    }
}

// Hook Objective-C 类中的方法
function hookObjCClassMethods(className) {
    var objc = ObjC.classes[className];
    if (objc !== undefined) {
        console.log('[*] Hooking class: ' + className);
        for (var methodName in objc) {
            if (objc.hasOwnProperty(methodName)) {
                try {
                    var method = objc[methodName];
                    Interceptor.attach(method, {
                        onEnter: function(args) {
                            console.log('[*] Called method: ' + methodName);
                            // 可以进一步分析方法参数
                        },
                        onLeave: function(retval) {
                            console.log('[*] Method ' + methodName + ' returned');
                        }
                    });
                } catch (e) {
                    console.log('[!] Error hooking method ' + methodName + ': ' + e.message);
                }
            }
        }
    } else {
        console.log('[!] Class ' + className + ' not found');
    }
}

// 解析并分析目标进程中的模块
function analyzeTargetModule() {
    // 获取加载的模块列表
    var modules = Process.enumerateModulesSync();
    console.log('[*] Loaded modules:');
    modules.forEach(function(module) {
        console.log('Module name: ' + module.name);
        if (module.name.indexOf('lib') !== -1 || module.name.indexOf('framework') !== -1) {
            targetModule = module.name;
            console.log('[*] Analyzing module: ' + targetModule);
            // 你可以在这里添加更多模块的分析代码
            traceFunctionCalls('someFunctionInModule'); // 示例，替换为目标函数名称
        }
    });
}

// Hook Objective-C 的类和方法
function hookObjCClasses() {
    var classes = ObjC.classes;
    console.log('[*] Hooking Objective-C classes...');
    for (var className in classes) {
        if (classes.hasOwnProperty(className)) {
            hookObjCClassMethods(className);
        }
    }
}

// 入口函数
function main() {
    // 获取目标进程
    targetProcess = Process.getCurrentThreadId();
    console.log('[*] Target process ID: ' + targetProcess);

    // 开始目标模块分析
    analyzeTargetModule();

    // 开始 Objective-C 类的 Hook
    hookObjCClasses();

    // 在此处可以添加更多自定义的分析逻辑
}

// 执行主函数
main();
