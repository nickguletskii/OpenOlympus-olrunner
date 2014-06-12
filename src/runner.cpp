/*******************************************************************************
 * This is a modification of simple2.c from the libsandbox project. The        *
 * licenses are provided below.                                                *
 ******************************************************************************/

/*******************************************************************************
 * LibSandbox command-line sandbox launcher                                    *
 *                                                                             *
 * Copyright (C) 2014 Nick Guletskii                                           *
 * All rights reserved.                                                        *
 *                                                                             *
 * Redistribution and use in source and binary forms, with or without          *
 * modification, are permitted provided that the following conditions are met: *
 *                                                                             *
 * 1. Redistributions of source code must retain the above copyright notice,   *
 *    this list of conditions and the following disclaimer.                    *
 *                                                                             *
 * 2. Redistributions in binary form must reproduce the above copyright        *
 *    notice, this list of conditions and the following disclaimer in the      *
 *    documentation and/or other materials provided with the distribution.     *
 *                                                                             *
 * 3. Neither the name of the author(s) nor the names of its contributors may  *
 *    be used to endorse or promote products derived from this software        *
 *    without specific prior written permission.                               *
 *                                                                             *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  *
 * POSSIBILITY OF SUCH DAMAGE.                                                 *
 ******************************************************************************/

/*******************************************************************************
 * The Sandbox Libraries (Core) - C Sample Program                             *
 *                                                                             *
 * Copyright (C) 2012-2013 LIU Yu, pineapple.liu@gmail.com                     *
 * All rights reserved.                                                        *
 *                                                                             *
 * Redistribution and use in source and binary forms, with or without          *
 * modification, are permitted provided that the following conditions are met: *
 *                                                                             *
 * 1. Redistributions of source code must retain the above copyright notice,   *
 *    this list of conditions and the following disclaimer.                    *
 *                                                                             *
 * 2. Redistributions in binary form must reproduce the above copyright        *
 *    notice, this list of conditions and the following disclaimer in the      *
 *    documentation and/or other materials provided with the distribution.     *
 *                                                                             *
 * 3. Neither the name of the author(s) nor the names of its contributors may  *
 *    be used to endorse or promote products derived from this software        *
 *    without specific prior written permission.                               *
 *                                                                             *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  *
 * POSSIBILITY OF SUCH DAMAGE.                                                 *
 ******************************************************************************/

/* check platform type */
#if !defined(__linux__) || !defined(__x86_64__)
#error "OpenOlympus only supports 64 bit Linux!"
#endif

#include "runner.hpp"

#include <sandbox.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sysexits.h>
#include <unistd.h>
#include <getopt.h>
#include <syscall.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>

namespace openolympus {

template<typename F, typename T>
T stream(F from) {
	std::stringstream ss;
	ss << from;
	T to;
	ss >> to;
	return to;
}

unsigned long timespecToMilliseconds(struct timespec timespec) {
	return timespec.tv_sec * 1000 + timespec.tv_nsec / 1000000;
}

const char* verdictFormatStrings[] = { "PENDING", "OK(%lu, %lu, %lu)",
		"SECURITY_VIOLATION(%d)", "MEMORY_LIMIT(%lu, %lu, %lu)",
		"OUTPUT_LIMIT(%lu, %lu, %lu)", "TIME_LIMIT(%lu, %lu, %lu)",
		"RUNTIME_ERROR(%lu, %lu, %lu)", "ABNORMAL_TERMINATION(%lu, %lu, %lu)",
		"INTERNAL_ERROR", "INCORRECT_SECURITY_CONFIG", "UNKNOWN", "UNKNOWN",
		"UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN" };

std::ofstream logFile("log.txt");
std::ofstream verdictFile("verdict.txt");
bool enableSecurity = true;
bool isSyscallAllowed(const syscall_t syscall, long a, long b, long c, long d,
		long e, long f) {
	switch (syscall.scno) {
	case SYS_restart_syscall:
	case SYS_read:
	case SYS_write:
	case SYS_lseek:
	case SYS_brk:
	case SYS_ioctl:
	case SYS_munmap:
	case SYS_mprotect:
	case SYS_mremap:
	case SYS_mmap:
	case SYS_gettid:
	case SYS_set_thread_area:
	case SYS_exit_group:
	case SYS_fstat:
	case SYS_uname:
	case SYS_arch_prctl:
	case SYS_access:
	case SYS_open:
	case SYS_close:
	case SYS_stat:
	case SYS_readv:
	case SYS_writev:
	case SYS_dup3:
	case SYS_rt_sigaction:
	case SYS_rt_sigprocmask:
	case SYS_rt_sigreturn:
	case SYS_tgkill:
	case SYS_getrlimit:
	case SYS_readlink:
	case SYS_time:
		return true;
	default:
		return !enableSecurity;
	}
}

void policyEventHandler(const policy_t* policy, const event_t* event,
		action_t* action) {
	assert(policy != nullptr);
	assert(event != nullptr);
	assert(action != nullptr);

	sandbox_container_t* sandbox = (sandbox_container_t*) policy->data;

	if ((event->type == S_EVENT_SYSCALL) || (event->type == S_EVENT_SYSRET)) {

		const syscall_t syscallInfo =
				*(const syscall_t*) &(event->data._SYSCALL.scinfo);

		if (isSyscallAllowed(syscallInfo, event->data._SYSCALL.a,
				event->data._SYSCALL.b, event->data._SYSCALL.c,
				event->data._SYSCALL.d, event->data._SYSCALL.e,
				event->data._SYSCALL.f)) {

			*action = (action_t ) { S_ACTION_CONT };

		} else {

			*action = (action_t ) { S_ACTION_KILL, { { S_RESULT_RF } } };
			sandbox->unauthorisedSyscallId = syscallInfo.scno;

			logFile << "UNAUTHORISED: Syscall " << syscallInfo.scno
					<< std::endl;
		}
		return;
	}

	((policy_entry_t) sandbox->defaultPolicy.entry)(&sandbox->defaultPolicy,
			event, action);
}

void policySetup(sandbox_container_t* sandbox) {
	assert(sandbox != nullptr);

	sandbox->defaultPolicy = sandbox->sbox.ctrl.policy;
	sandbox->defaultPolicy.entry =
			(sandbox->defaultPolicy.entry) ? : (void*) sandbox_default_policy;
	sandbox->sbox.ctrl.policy = (policy_t ) { (void*) policyEventHandler,
					(long) sandbox };
}
int run(int argc, char **argv) {
	rlim_t memoryLimit = 64 * 1024 * 1024 ;
	rlim_t cpuLimit = 1 * 1000;
	rlim_t timeLimit = 2 * 1000;
	rlim_t diskLimit = 1 * 1024 * 1024;
	std::string jailPath = "/";
	{
		int c;
		while (1) {
			static struct option long_options[] = {

			{ "memorylimit", required_argument, 0, 'm' },

			{ "cpulimit", required_argument, 0, 'c' },

			{ "timelimit", required_argument, 0, 't' },

			{ "disklimit", required_argument, 0, 'd' },

			{ "security", required_argument, 0, 's' },

			{ "jail", required_argument, 0, 'j' },

			{ 0, 0, 0, 0 } };

			int option_index = 0;
			c = getopt_long(argc, argv, "mctd", long_options, &option_index);
			if (c == -1)
				break;
			switch (c) {
			case 0:
				break;
			case 'm':
				memoryLimit = stream<char*, rlim_t>(optarg);
				break;
			case 'c':
				cpuLimit = stream<char*, rlim_t>(optarg);
				break;
			case 't':
				timeLimit = stream<char*, rlim_t>(optarg);
				break;
			case 'd':
				diskLimit = stream<char*, rlim_t>(optarg);
				break;
			case 's':
				enableSecurity = stream<char*, bool>(optarg);
				break;
			case 'j':
				jailPath = std::string(optarg);
				break;
			case '?':
				break;
			default:
				return EX_USAGE;
			}
		}
	}

	logFile << "Starting sandbox with limits:" << std::endl << "memory "
			<< memoryLimit << std::endl << "cpu " << cpuLimit << std::endl
			<< "time " << timeLimit << std::endl << "disk " << diskLimit
			<< " and chroot path \"" << jailPath << "\"" << std::endl;
	logFile << "Arguments: ";
	for (size_t index = optind; index < argc; index++)
		logFile << argv[index] << " ";
	logFile << std::endl;

	const char** childArgv = const_cast<const char**>(&argv[optind]);

	sandbox_container_t sandbox;

	if (sandbox_init(&sandbox.sbox, childArgv) != 0) {
		logFile << "Sandbox initialization failed!" << std::endl;
		verdictFile << "INTERNAL_ERROR" << std::endl;
		return EX_DATAERR;
	}

	policySetup(&sandbox);

	sandbox.sbox.task.ifd = STDIN_FILENO;
	sandbox.sbox.task.ofd = STDOUT_FILENO;
	sandbox.sbox.task.efd = STDERR_FILENO;
	strcpy(sandbox.sbox.task.jail, jailPath.c_str());
	logFile << "Jail path: " << std::string(sandbox.sbox.task.jail)
			<< std::endl;
	sandbox.sbox.task.quota[S_QUOTA_WALLCLOCK] = timeLimit;
	sandbox.sbox.task.quota[S_QUOTA_CPU] = cpuLimit;
	sandbox.sbox.task.quota[S_QUOTA_MEMORY] = memoryLimit;
	sandbox.sbox.task.quota[S_QUOTA_DISK] = diskLimit;
	if (!sandbox_check(&sandbox.sbox)) {
		logFile << "Sandbox self-check failed" << std::endl;
		verdictFile << "INTERNAL_ERROR" << std::endl;
		return EX_DATAERR;
	}

	result_t result = *sandbox_execute(&sandbox.sbox);

	char buf[1024];
	switch (result) {
	case S_RESULT_OK:
	case S_RESULT_ML:
	case S_RESULT_OL:
	case S_RESULT_TL:
	case S_RESULT_RT:
	case S_RESULT_AT:
		sprintf(buf, verdictFormatStrings[result],
				timespecToMilliseconds(sandbox.sbox.stat.elapsed),
				timespecToMilliseconds(sandbox.sbox.stat.cpu_info.clock),
				sandbox.sbox.stat.mem_info.vsize_peak / (1024 * 1024));
		verdictFile << std::string(buf) << std::endl;
		break;
	case S_RESULT_RF:
		sprintf(buf, verdictFormatStrings[result],
				sandbox.unauthorisedSyscallId);
		verdictFile << std::string(buf) << std::endl;
		break;
	default:
		verdictFile << std::string(verdictFormatStrings[result]) << std::endl;
		break;
	}
	sandbox_fini(&sandbox.sbox);
	return EX_OK;
}
}

int main(int argc, char **argv) {
	openolympus::run(argc, argv);
}
