#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string.h>
#include <Windows.h>

using namespace std;

#define Path_Config_File "C:\\Users\\Admin\\Desktop\\fuzzer\\config_16"
string Path_EXE = "C:\\Users\\Admin\\Desktop\\fuzzer\\vuln16.exe";

FILE* conf_file;
FILE* log_file;
char* buffer_config = NULL;
char* buffer_origin = NULL;
unsigned int buffer_size;
unsigned int size_origin;
unsigned int header_size;

void OpenConfigFile()
{
	conf_file = fopen(Path_Config_File, "rb+");
	if (!conf_file)
	{
		cout << "Error in opening the file" << endl;
		return;
	}
	fseek(conf_file, 0, SEEK_END);
	buffer_size = ftell(conf_file);
	size_origin = buffer_size;
	fseek(conf_file, 0, SEEK_SET);

	buffer_config = new char[buffer_size + 1];
	buffer_origin = new char[buffer_size + 1];


	if (fread(buffer_config, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error in opening the file" << endl;
		return;
	}
	memcpy(buffer_origin, buffer_config, buffer_size);

	char* ptr = (char*)memchr(buffer_config, '/', buffer_size);
	header_size = ptr - buffer_config;

	log_file = fopen("log.txt", "w");
	if (!log_file)
	{
		cout << "Error in opening the file" << endl;
		return;
	}
}

void ChangeOneByte(unsigned int byte, unsigned int offset)
{
	buffer_config[offset] = byte;
	fseek(conf_file, 0, SEEK_SET);
	if (fwrite(buffer_config, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error writing to file" << endl;
		return;
	}
	fflush(conf_file);

	fprintf(log_file, "Change %i : 0x%x\n", offset, byte);
	fflush(log_file);
}

void ChangeMultipleBytes(unsigned int byte, unsigned int offset, unsigned int quantity)
{
	int s = quantity + offset;
	fprintf(log_file, "Change %i : 0x%x (%d quantity)\n", offset, byte, quantity);

	if (s < buffer_size)
	{
		while (offset < s)
		{
			buffer_config[offset] = byte;
			offset++;
		}

	}
	else
	{
		buffer_size += quantity;
		buffer_config = (char*)realloc(buffer_config, buffer_size);
		while (offset < buffer_size)
		{
			buffer_config[offset] = byte;
			offset++;
		}
	}
	fseek(conf_file, 0, SEEK_SET);
	if (fwrite(buffer_config, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error writing to file" << endl;
		return;
	}
	fflush(conf_file);
}

void WriteEndFile(unsigned int byte, unsigned int quantity)
{
	unsigned int size_new = buffer_size + quantity;
	buffer_config = (char*)realloc(buffer_config, size_new);

	while (buffer_size < size_new)
	{
		buffer_config[buffer_size] = byte;
		buffer_size++;
	}
	fseek(conf_file, 0, SEEK_SET);
	if (fwrite(buffer_config, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error writing to file" << endl;
		return;
	}
	fflush(conf_file);
}

void ChangeHeader(unsigned int byte, unsigned int quantity)
{
	string buf(buffer_config, buffer_size);
	buf.insert(header_size, quantity, byte);
	buffer_config = (char*)realloc(buffer_config, buf.size());
	memcpy(buffer_config, buf.c_str(), buf.size());
	buffer_size = buf.size();

	fseek(conf_file, 0, SEEK_SET);
	if (fwrite(buffer_config, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error writing to file" << endl;
		return;
	}
	fflush(conf_file);

}

void OriginConfigFile()
{
	delete[] buffer_config;
	buffer_config = new char[size_origin + 1];
	memcpy(buffer_config, buffer_origin, size_origin);
	buffer_size = size_origin;
	fclose(conf_file);
	conf_file = fopen(Path_Config_File, "wb");
	if (fwrite(buffer_origin, 1, buffer_size, conf_file) != buffer_size)
	{
		cout << "Error writing to file" << endl;
		return;
	}
	fflush(conf_file);
}

void GetRegisterStates(DEBUG_EVENT DebugEvent, const char* error, HANDLE hProcess)
{
	unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;

	HANDLE thread;
	CONTEXT cont;

	thread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (thread == NULL)
	{
		cout << "OpenThread failed: " << dec << GetLastError() << endl;
		return;
	}

	cont.ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(thread, &cont) == false)
	{
		cout << "GetThreadContext failed: " << dec << GetLastError() << endl;
		CloseHandle(thread);
		return;
	}

	FILE* RegFile = fopen("RegisterStates.txt", "a");

	fprintf(RegFile, "Error: %s\n", error);
	fprintf(RegFile, "eax : 0x%p\n", cont.Eax);
	fprintf(RegFile, "ebx : 0x%p\n", cont.Ebx);
	fprintf(RegFile, "ecx : 0x%p\n", cont.Ecx);
	fprintf(RegFile, "edx : 0x%p\n", cont.Edx);
	fprintf(RegFile, "eip : 0x%p\n", cont.Eip);
	fprintf(RegFile, "esp : 0x%p\n", cont.Esp);
	fprintf(RegFile, "ebp : 0x%p\n", cont.Ebp);
	fprintf(RegFile, "edi : 0x%p\n", cont.Edi);
	fprintf(RegFile, "esi : 0x%p\n", cont.Esi);
	fprintf(RegFile, "flg : 0x%p\n", cont.EFlags);

	ReadProcessMemory(hProcess, (void*)cont.Esp, buffer, sizeof(buffer), &recvSize);
	if (recvSize != 0)
	{
		fprintf(RegFile, "\nStack (%d bytes read):\n", recvSize);
		for (int i = 0; i < recvSize; i++)
		{
			if ((i + 1) % 4 == 1)
			{
				fprintf(RegFile, "0x%p : ", (void*)((char*)cont.Esp + i));
			}
			if (buffer[i] < 0x10)
			{
				fprintf(RegFile, "0");
			}
			fprintf(RegFile, "%X ", (int)buffer[i]);
			if ((i + 1) % 4 == 0)
			{
				fprintf(RegFile, "\n");
			}
		}
	}
	fprintf(RegFile, "\n");
	fclose(RegFile);
}

bool Start()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	string dir_exe = "C:\\Users\\Admin\\Desktop\\fuzzer";
	if (CreateProcessA(Path_EXE.c_str(), NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, dir_exe.c_str(), &si, &pi) == false)
	{
		cout << "CreateProcess failed: " << dec << GetLastError() << endl;
		return false;
	}
	DEBUG_EVENT DebugEvent;

	while (1)
	{
		if (WaitForDebugEvent(&DebugEvent, 500) == 0)
		{
			if (GetLastError() != ERROR_SEM_TIMEOUT)
			{
				cout << "WAIT FOR DEBUG EVENT ERROR : " << GetLastError() << endl;
			}
			break;
		}
		if (DebugEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
			continue;
		}
		switch (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_ACCESS_VIOLATION:
		{
			cout << "Access Violation" << endl;
			GetRegisterStates(DebugEvent, "Access Violation", pi.hProcess);
			return true;
		}
		case EXCEPTION_STACK_OVERFLOW:
		{
			cout << "Stack overflow" << endl;
			GetRegisterStates(DebugEvent, "Stack overflow", pi.hProcess);
			return true;
		}
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		{
			cout << "ARRAY BOUNDS EXCEEDED" << endl;
			GetRegisterStates(DebugEvent, "ARRAY BOUNDS EXCEEDED", pi.hProcess);
			return true;
		}
		case EXCEPTION_DATATYPE_MISALIGNMENT:
		{
			cout << "DATATYPE MISALIGNMENT" << endl;
			GetRegisterStates(DebugEvent, "DATATYPE MISALIGNMENT", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_DENORMAL_OPERAND:
		{
			cout << "FLT DENORMAL OPERAND" << endl;
			GetRegisterStates(DebugEvent, "FLT DENORMAL OPERAND", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		{
			cout << "FLT DIVIDE BY ZERO" << endl;
			GetRegisterStates(DebugEvent, "FLT DIVIDE BY ZERO", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_INEXACT_RESULT:
		{
			cout << "FLT INEXACT RESULT" << endl;
			GetRegisterStates(DebugEvent, "FLT INEXACT RESULT", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_INVALID_OPERATION:
		{
			cout << "FLT INVALID OPERATION" << endl;
			GetRegisterStates(DebugEvent, "FLT INVALID OPERATION", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_OVERFLOW:
		{
			cout << "FLT OVERFLOW" << endl;
			GetRegisterStates(DebugEvent, "FLT OVERFLOW", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_STACK_CHECK:
		{
			cout << "FLT STACK CHECK" << endl;
			GetRegisterStates(DebugEvent, "FLT STACK CHECK", pi.hProcess);
			return true;
		}
		case EXCEPTION_FLT_UNDERFLOW:
		{
			cout << "FLT UNDERFLOW" << endl;
			GetRegisterStates(DebugEvent, "FLT UNDERFLOW", pi.hProcess);
			return true;
		}
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		{
			cout << "ILLEGAL INSTRUCTION" << endl;
			GetRegisterStates(DebugEvent, "ILLEGAL INSTRUCTION", pi.hProcess);
			return true;
		}
		case EXCEPTION_IN_PAGE_ERROR:
		{
			cout << "IN PAGE ERROR" << endl;
			GetRegisterStates(DebugEvent, "IN PAGE ERROR", pi.hProcess);
			return true;
		}
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
		{
			cout << "INT_DIVIDE_BY_ZERO" << endl;
			GetRegisterStates(DebugEvent, "INT_DIVIDE_BY_ZERO", pi.hProcess);
			return true;
		}
		case EXCEPTION_INT_OVERFLOW:
		{
			cout << "INT_OVERFLOW" << endl;
			GetRegisterStates(DebugEvent, "INT_OVERFLOW", pi.hProcess);
			return true;
		}
		case EXCEPTION_INVALID_DISPOSITION:
		{
			cout << "INVALID_DISPOSITION" << endl;
			GetRegisterStates(DebugEvent, "INVALID_DISPOSITION", pi.hProcess);
			return true;
		}
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		{
			cout << "NONCONTINUABLE_EXCEPTION" << endl;
			GetRegisterStates(DebugEvent, "NONCONTINUABLE_EXCEPTION", pi.hProcess);
			return true;
		}
		case EXCEPTION_PRIV_INSTRUCTION:
		{
			cout << "PRIV_INSTRUCTION" << endl;
			GetRegisterStates(DebugEvent, "PRIV_INSTRUCTION", pi.hProcess);
			return true;
		}
		case EXCEPTION_SINGLE_STEP:
		{
			cout << "SINGLE_STEP" << endl;
			GetRegisterStates(DebugEvent, "SINGLE_STEP", pi.hProcess);
			return true;
		}

		default:
		{
			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}
		}
	}
	return false;
}

void AutoMode()
{
	for (int i = 1; i < header_size; i++)
	{
		ChangeMultipleBytes(0xff, 0x36, 100000);
		ChangeOneByte(0x00, i);
		if (Start())
		{
			return;
		}
		ChangeOneByte(0xff, i);
		if (Start())
		{
			return;
		}
		ChangeOneByte(0x7f, i);
		if (Start())
		{
			return;
		}
		OriginConfigFile();
	}

	ChangeMultipleBytes(0xff, 0x36, 100000);
	for (int i = 1; i < header_size; i++)
	{
		for (int j = 2; j < 20; j++)
		{
			ChangeMultipleBytes(0x00, i, j);
			if (Start())
			{
				return;
			}
			ChangeMultipleBytes(0xff, i, j);
			if (Start())
			{
				return;
			}
			ChangeMultipleBytes(0x7f, i, j);
			if (Start())
			{
				return;
			}
		}
		OriginConfigFile();
		ChangeMultipleBytes(0xff, 0x36
			, 100000);
	}

}





int main()
{
	OpenConfigFile();
	
	int n;
	unsigned int byte, offset, quantity;

	while (1)
	{
		cout << "Please, make your choice: \n1. Replacing 1 byte\n2. Replacing multiple bytes\n3. Writing to the end of the file\n"
			"4. Writing to the end of the header\n5. Return to the original file\n6. Start program\n7. Auto mode\n"
			"8. Code Coverage\n" << endl;
		cin >> n;

		switch (n)
		{
			case 1:
			{
				cout << "Enter a value: ";
				cin >> hex >> byte;
				cout << "Enter an offset: ";
				cin >> offset;
				ChangeOneByte(byte, offset);
				break;
			}
			case 2:
			{
				cout << "Enter a value: ";
				cin >> hex >> byte;
				cout << "Enter an offset: ";
				cin >> offset;
				cout << "Enter the quantity: ";
				cin >> dec >> quantity;
				ChangeMultipleBytes(byte, offset, quantity);
				break;
			}
			case 3:
			{
				cout << "Enter a value: ";
				cin >> hex >> byte;
				cout << "Enter the quantity: ";
				cin >> dec >> quantity;
				WriteEndFile(byte, quantity);
				break;
			}
			case 4:
			{
				cout << "Enter a value: ";
				cin >> hex >> byte;
				cout << "Enter the quantity: ";
				cin >> quantity;
				ChangeHeader(byte, quantity);
				break;
			}
			case 5:
			{
				OriginConfigFile();
				break;
			}
			case 6:
			{
				Start();
				break;
			}
			case 7:
			{
				AutoMode();
				break;
			}
			case 8:
			{
				system("cd C:\\Users\\Admin\\Desktop\\DynamoRIO-Windows-10.0.0\\bin32\\");
				system("C:\\Users\\Admin\\Desktop\\DynamoRIO-Windows-10.0.0\\bin32\\drrun.exe -t drcov -dump_text -- C:\\Users\\Admin\\Desktop\\fuzzer\\vuln16.exe");
				break;
			}
			default:
			{
				fclose(conf_file);
				exit(1);
			}
		}
	}

}
