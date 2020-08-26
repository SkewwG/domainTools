#include "TaskScheduler.h"


void TaskSche::CopySelf()
{
	WCHAR pathF[MAX_LEN_FILENAME];
	GetModuleFileName(NULL, pathF, sizeof(pathF));
	WCHAR dest[] = _T("C:\\windows\\temp\\tempsh.exe");
	wprintf(L"%s", pathF);
	CopyFile(pathF, dest, false);
}


void TaskSche::copyFile(string source, string dest) {
	ifstream  src(source, ios::binary);
	ofstream  dst(dest, ios::binary);
	dst << src.rdbuf();
	dst.close();
	src.close();
}


int TaskSche::isFileExist(LPSTR lpFilePath)
{
	/* Check for existence */
	if ((_access(lpFilePath, 0)) != -1)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


int TaskSche::TaskAdd(LPCWSTR wszTaskName, wstring wstrTaskTime, wstring wstrProgram, wstring args)
{
	// https://docs.microsoft.com/zh-cn/windows/win32/taskschd/time-trigger-example--c---
	// https://docs.microsoft.com/zh-cn/windows/win32/taskschd/daily-trigger-example--c---

	setlocale(LC_ALL, "");

	// 初始化COM组件
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return 1;
	}


	// 设置组件安全等级
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return 1;
	}

	// 设置计划任务名字 
	// LPCWSTR wszTaskName = L"StateGrid";
	wprintf(L"TaskName:%s\n", wszTaskName);

	// 设置执行路径
	wstring wstrExePath = _wgetenv(_bstr_t(L"WINDIR"));		// 获取宽字符的环境变量
	wstrExePath += L"\\SYSTEM32\\";
	wstrExePath += wstrProgram;


	// 创建任务服务容器 
	// Link: https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itaskservice		
	// https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return 1;
	}

	// 连接目标服务器为远程连接或本地服务器   https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-connect
	hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());	//默认本地
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}

	// 获取任务文件夹并在其中创建任务
	ITaskFolder* pRootFolder = NULL;   https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-getfolder
	// 计划任务路径
	hr = pService->GetFolder(_bstr_t(L"\\Microsoft\\Windows\\AppID"), &pRootFolder);			// _bstr_t 将wstr转换为bstr
	if (FAILED(hr))
	{
		printf("Cannot get Root folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	wprintf(L"Task Path：\\Microsoft\\Windows\\AppID\n");

	// 检测是否已经创建计划任务
	IRegisteredTask* pExistingTask = NULL;
	hr = pRootFolder->GetTask(_bstr_t(wszTaskName), &pExistingTask);
	if (hr == S_OK)
	{
		printf("Task exist!\n");
		return 1;
	}
	printf("Create New Task\n");

	// 如果存在同名任务，删除它
	// pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	// 创建计划任务定义对象来创建计划任务。
	ITaskDefinition* pTask = NULL;				// https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itaskdefinition
	hr = pService->NewTask(0, &pTask);				// https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-newtask
	pService->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return 1;
	}


	// 使用IRegistrationInfo对象对任务的基础信息填充		
	// https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iregistrationinfo
	// 获取或设置用于描述任务的注册信息，例如任务的描述，任务的作者以及任务的注册日期。 
	// ITaskDefinition :: get_RegistrationInfo   https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskdefinition-get_registrationinfo
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	// 设置作者名字
	hr = pRegInfo->put_Author(_bstr_t(L"Microsoft Corporation"));
	pRegInfo->Release();
	if (FAILED(hr))
	{
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}




	// 创建任务的安全凭证		https://docs.microsoft.com/zh-cn/windows/win32/api/taskschd/nn-taskschd-iprincipal
	IPrincipal* pPrincipal = NULL;
	hr = pTask->get_Principal(&pPrincipal);		// 获取或设置任务的主体，该主体提供任务的安全凭据。
	if (FAILED(hr))
	{
		printf("\nCannot get principal pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	// 设置规则为交互式登录
	pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);		// 使用用户当前的登录信息
	//pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
	pPrincipal->put_UserId(_bstr_t(L"NT AUTHORITY\\SYSTEM"));		// 以system权限执行，所以当前用户权限需要是管理员权限

	// 创建任务的设置信息,即计划任务选项里的设置里的各种信息		https://docs.microsoft.com/zh-cn/windows/win32/api/taskschd/nn-taskschd-itasksettings
	ITaskSettings* pTaskSettings = NULL;
	pTask->get_Settings(&pTaskSettings);

	// 为设置信息赋值
	pTaskSettings->put_StartWhenAvailable(VARIANT_TRUE);			// 默认为VARIANT_TRUE	https://docs.microsoft.com/zh-cn/windows/win32/api/taskschd/nf-taskschd-itasksettings-put_startwhenavailable

	// 设置任务的idle设置
	IIdleSettings* pIdleSettings = NULL;
	pTaskSettings->get_IdleSettings(&pIdleSettings);
	pIdleSettings->put_WaitTimeout(_bstr_t(L"PT5M"));

	// 设置任务的并行运行，即运行一次任务后，还能够继续再运行
	pTaskSettings->put_MultipleInstances(TASK_INSTANCES_PARALLEL);			//  https://docs.microsoft.com/zh-cn/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_multipleinstances   https://docs.microsoft.com/zh-cn/windows/win32/taskschd/taskschedulerschema-multipleinstancespolicytype-simpletype


	//创建触发器
	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);			// 获取或设置用于启动任务的触发器的集合。
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	ITrigger* pTrigger = NULL;

	// 触发器
	/*
	各种条件下触发：https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itriggercollection-create
	属性：https://docs.microsoft.com/en-us/windows/win32/api/mstask/ns-mstask-task_trigger
	https://docs.microsoft.com/zh-cn/windows/win32/api/mstask/nf-mstask-itasktrigger-settrigger
	TASK_TRIGGER_LOGON: 当特定用户登录时触发任务。
	TASK_TRIGGER_TIME: 在一天的特定时间触发任务。
	*/

	// 延时触发器
	/*
	定义任务运行的频率以及任务启动后重复重复模式的时间：https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-irepetitionpattern

	ITrigger :: put_StartBoundary 设置激活触发器的日期和时间。日期和时间必须采用以下格式：YYYY-MM-DDTHH：MM：SS（+-）HH：MM。格式的（+-）HH：MM部分定义了协调世界时（UTC）之前或之后的特定小时数和分钟数。例如，2005年10月11日1:21:17的日期与UTC的时间相差八小时，则将其写为2005-10-11T13：21：17
	https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itrigger-put_startboundary

	repetitionType 指定模式重复的时间。此字符串的格式为PnYnMnDTnHnMnS，其中nY是年数，nM是月数，nD是天数，“ T”是日期/时间分隔符，nH是小时数，nM是分钟数，nS是秒数（例如，PT5M指定5分钟，P1M4DT2H5M指定一个月，四天，两小时和五分钟）。
	https://docs.microsoft.com/zh-cn/windows/win32/taskschd/taskschedulerschema-duration-repetitiontype-element


	*/

	// 每次
	hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	pTriggerCollection->Release();
	ITimeTrigger* pTimeTrigger = NULL;
	pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
	pTimeTrigger->put_Id(_bstr_t(L"Trigger0"));
	pTimeTrigger->put_StartBoundary(_bstr_t(L"2000-04-01T00:00:00"));		// 设置激活触发器的日期和时间:从2000-04-01开始，每天的00:00:00触发
	pTimeTrigger->put_EndBoundary(_bstr_t(L"2030-05-02T23:59:59"));		// 设置停用触发器的日期和时间:到2030-05-02 23:59:59结束
	IRepetitionPattern* pRepetitionPattern = NULL;
	pTimeTrigger->get_Repetition(&pRepetitionPattern);
	pTimeTrigger->Release();
	pRepetitionPattern->put_Duration(_bstr_t(L""));			// 设置模式重复的时间。如果在持续时间内未指定任何值，则该模式将无限期重复
	// pRepetitionPattern->put_Interval(_bstr_t(L"PT30M"));			// 设置每次重新启动任务之间的时间。每隔多久触发
	pRepetitionPattern->put_Interval(_bstr_t(wstrTaskTime.data()));			// 设置每次重新启动任务之间的时间。每隔多久触发
	pRepetitionPattern->Release();



	// 每天
	/*
	hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
	pTriggerCollection->Release();
	IDailyTrigger* pDailyTrigger = NULL;
	pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger);
	pDailyTrigger->put_Id(_bstr_t(L"Trigger0"));
	pDailyTrigger->put_StartBoundary(_bstr_t(L"2000-04-01T00:00:00"));		// 设置激活触发器的日期和时间:从2000-04-01开始，每天的00:00:00触发
	pDailyTrigger->put_EndBoundary(_bstr_t(L"2030-05-02T23:59:59"));		// 设置停用触发器的日期和时间:到2030-05-02 23:59:59结束
	pDailyTrigger->put_DaysInterval((short)1);								// 设置计划中各天之间的间隔：间隔1产生每日计划。间隔2产生每隔一天的时间表
	IRepetitionPattern* pRepetitionPattern = NULL;
	pDailyTrigger->get_Repetition(&pRepetitionPattern);
	pDailyTrigger->Release();
	pRepetitionPattern->put_Duration(_bstr_t(L""));			// 设置模式重复的时间。如果在持续时间内未指定任何值，则该模式将无限期重复
	pRepetitionPattern->put_Interval(_bstr_t(L"PT1M"));			// 设置每次重新启动任务之间的时间。每隔多久触发
	pRepetitionPattern->Release();
	*/


	// 时间触发器
	/*
	pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	ITimeTrigger* pTimeTrigger = NULL;
	pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
	pTimeTrigger->put_Id(_bstr_t(L"Trigger1"));
	pTimeTrigger->put_EndBoundary(_bstr_t(L"2020-03-29T20:00:00"));
	pTimeTrigger->put_StartBoundary(_bstr_t(L"2020-03-26T13:00:00"));
	*/

	// 登录触发器
	/*
	pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
	ILogonTrigger* pLogonTrigger = NULL;
	pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
	pLogonTrigger->put_Id(_bstr_t(L"Trigger2"));
	//pLogonTrigger->put_UserId(_bstr_t(L"desktop-gdep6gd\\user"));
	//pLogonTrigger->put_EndBoundary(_bstr_t(L"2020-03-29T20:00:00"));
	pLogonTrigger->put_StartBoundary(_bstr_t(L"2020-03-25T20:00:00"));
	*/


	// 启动触发器
	/*
	pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
	IBootTrigger* pBootTrigger;
	pTrigger->QueryInterface(IID_IBootTrigger, (void**)&pBootTrigger);
	pBootTrigger->put_Id(_bstr_t(L"Trigger3"));
	pBootTrigger->put_EndBoundary(_bstr_t(L"2020-03-29T20:00:00"));
	pBootTrigger->put_StartBoundary(_bstr_t(L"2020-03-25T20:00:00"));
	*/

	// 创建任务动作
	IActionCollection* pActionCollection = NULL;
	pTask->get_Actions(&pActionCollection);
	IAction* pAction = NULL;
	pActionCollection->Create(TASK_ACTION_EXEC, &pAction);		// TASK_ACTION_EXEC: 该操作执行命令行操作。例如，该操作可以运行脚本，启动可执行文件，或者，如果提供了文档名称，则找到其关联的应用程序并使用文档启动应用程序。
	IExecAction* pExecAction = NULL;							// IExecAction 表示执行命令行操作的操作。
	pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pExecAction->put_Path(_bstr_t(wstrExePath.c_str()));		// 获取或设置可执行文件的路径。
	pExecAction->Release();

	// 执行程序的参数

	// wstring args(L"/c C:\\windows\\temp\\StateGrid.exe");
	// args.append(cmd);
	// args += argv[2];

	wprintf(L"Command:%s %s\n", wstrProgram.data(), args.data());
	pExecAction->put_Arguments(_bstr_t(args.data()));


	// pExecAction->put_Arguments(_bstr_t(L"/c calc"));

	IRegisteredTask* pRegistredTask = NULL;
	pRootFolder->RegisterTaskDefinition(_bstr_t(wszTaskName), pTask, TASK_CREATE_OR_UPDATE,
		_variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(), &pRegistredTask);

	cout << "\n 创建任务完成.\n" << endl;
	wprintf(L"**********\n");
	CoUninitialize();
	return 0;

}