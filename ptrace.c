#include <Python.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>


PyDoc_STRVAR(ptrace_read_memory_doc, "read a word at the address addr in the tracee's memory, returning the word as the result");

static PyObject *
ptrace_read_memory(PyObject *object, PyObject *args)
{ 
	pid_t pid;
	unsigned long ret; 
	unsigned long len;
	unsigned long addr;
	unsigned long *buffer; 
	PyObject *ret_object;

	if (!PyArg_ParseTuple(args, "Ikk:read_memory",  &pid, &addr, &len)) {
		return NULL;
	} 

	buffer = PyMem_Malloc(len + sizeof(unsigned long)); 

	unsigned t = len / sizeof(unsigned long); 
	if (len % sizeof(unsigned long) > 0) {
		t += 1;
	}
	unsigned long *tmp = buffer;
	unsigned i; 
	for(i=0; i < t; i++) { 
		ret = ptrace(PTRACE_PEEKDATA,
				pid,
				(unsigned long *)addr + i,
				NULL); 
		if (ret < 0) {
			PyMem_Free(buffer);
			PyErr_SetFromErrno(PyExc_OSError);
			return NULL; 
		} 
		*(tmp+i) = ret; 
	} 
	ret_object = PyString_FromStringAndSize((void *)buffer, len);
	PyMem_Free(buffer); 
	return ret_object;
}


PyDoc_STRVAR(ptrace_write_memory_doc, "copy the word data to the address addr in the tracee's memory");

static PyObject *
ptrace_write_memory(PyObject *object, PyObject *args)
{ 
	pid_t pid;	
	unsigned long ret; 
	unsigned long len;
	unsigned long addr;
	unsigned long *buffer;
	PyObject * data;

	if (!PyArg_ParseTuple(args, "IkO:write_memory", &pid, &addr, &data)) {
		return NULL;
	}

	if (!PyString_Check(data)) {
		PyErr_SetString(PyExc_TypeError, "data: need a str");
		return NULL;
	} 
	/* copy to local buffer */
	len = PyString_GET_SIZE(data);	
	buffer = PyMem_Malloc(len); 
	memcpy(buffer, PyString_AS_STRING(data), len); 

	unsigned t = len / sizeof(unsigned long);
	/* copy, align unsigned long*/		
	unsigned i;
	for(i = 0; i < t; i++) { 
		ret = ptrace(PTRACE_POKEDATA,
				pid,
				(unsigned long *)addr + i,
				(void *)(unsigned long)*buffer);
		if (ret < 0) {
			goto failed;
		}
		buffer += 1;
	} 
	/* copy the rest */ 
	ret = ptrace(PTRACE_PEEKDATA,
			pid,
			(unsigned long *)addr + i,
			NULL); 
	if (ret < 0) {
		goto failed;
	}
	memcpy(&ret, (void *)buffer, len % sizeof(unsigned long)); 

	ret = ptrace(PTRACE_POKEDATA,
			pid, 
			(unsigned long *)addr + i,
			(void *)ret);
	if (ret < 0) {
		goto failed;
	} 
	PyMem_Free(buffer);
	Py_RETURN_NONE; 
failed:
	PyMem_Free(buffer);
	PyErr_SetFromErrno(PyExc_OSError);
	return NULL;
}


PyDoc_STRVAR(ptrace_attach_doc, "attach to the process specified in pid, making it a tracee of the calling process.");

static PyObject *
ptrace_attach(PyObject *object, PyObject *args)
{
	pid_t pid;
	int ret;
	if (!PyArg_ParseTuple(args, "I:attach", &pid)) {
		return NULL;
	}
	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}


PyDoc_STRVAR(ptrace_detach_doc, "restart the stopped tracee");

static PyObject *
ptrace_detach(PyObject *object, PyObject *args)
{
	pid_t pid;
	int ret;
	if (!PyArg_ParseTuple(args, "I:detach", &pid)) {
		return NULL; 
	}
	ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	Py_RETURN_NONE;
}


PyDoc_STRVAR(ptrace_kill_doc, "send the tracee a SIGKILL to terminate it");

static PyObject *
ptrace_kill(PyObject *object, PyObject *args)
{
	pid_t pid;
	int ret;
	if (!PyArg_ParseTuple(args, "I:kill", &pid)) {
		return NULL;
	}
	ret = ptrace(PTRACE_KILL, pid, NULL, NULL);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;

}


PyDoc_STRVAR(ptrace_cont_doc, "restart the stopped tracee process");

static PyObject *
ptrace_cont(PyObject *object, PyObject *args)
{
	pid_t pid; 
	int ret;
	unsigned long data = 0;

	if (!PyArg_ParseTuple(args, "Ik:cont", &pid, &data)) {
		return NULL;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, (void *)data);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;
}



PyDoc_STRVAR(ptrace_sysemu_doc, "continue and stop on entry to the next system call, which will not be executed");

static PyObject *
ptrace_sysemu(PyObject *object, PyObject *args)
{
	pid_t pid; 
	int ret;
	unsigned long data = 0;

	if (!PyArg_ParseTuple(args, "Ik:sysemu", &pid, &data)) {
		return NULL;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, (void *)data);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;
}

PyDoc_STRVAR(ptrace_sysemu_single_doc, "do the same but also singlestep if not a system call");

static PyObject *
ptrace_sysemu_single(PyObject *object, PyObject *args)
{
	pid_t pid; 
	int ret;
	unsigned long data = 0;

	if (!PyArg_ParseTuple(args, "Ik:sysemu_single", &pid, &data)) {
		return NULL;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, (void *)data);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE;
}


PyDoc_STRVAR(ptrace_syscall_doc, "restart the stopped tracee as for cont, but arrange for the tracee to be stopped at the next entry to or exit from a system call.");

static PyObject *
ptrace_syscall(PyObject *object, PyObject *args)
{ 
	pid_t pid; 
	int ret;
	unsigned long data = 0;

	if (!PyArg_ParseTuple(args, "Ik:syscall", &pid, &data)) {
		return NULL;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, (void *)data);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}


PyDoc_STRVAR(ptrace_singlestep_doc, "restart the stopped tracee as for cont, but arrange for the tracee to be stopped at the next entry to or exit from a system call after execution of a single instruction.");

static PyObject *
ptrace_singlestep(PyObject *object, PyObject *args)
{ 
	pid_t pid; 
	int ret;
	unsigned long data = 0;

	if (!PyArg_ParseTuple(args, "Ik:singlestep", &pid, &data)) {
		return NULL;
	}
	ret = ptrace(PTRACE_CONT, pid, NULL, (void *)data);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	Py_RETURN_NONE; 
}


static inline void 
add_regs_to_dict(PyObject *regs_dict, struct user_regs_struct *regs)
{

#ifndef __x86_64_

#define DICT_ADD_ULONG(x, y, z) PyDict_SetItemString(x, y, PyLong_FromUnsignedLong(z))
	DICT_ADD_ULONG(regs_dict, "r15", regs->r15);
	DICT_ADD_ULONG(regs_dict, "r14", regs->r14);
	DICT_ADD_ULONG(regs_dict, "r13", regs->r13);
	DICT_ADD_ULONG(regs_dict, "r12", regs->r12);
	DICT_ADD_ULONG(regs_dict, "rbp", regs->rbp);
	DICT_ADD_ULONG(regs_dict, "rbx", regs->rbx);
	DICT_ADD_ULONG(regs_dict, "r11", regs->r11);
	DICT_ADD_ULONG(regs_dict, "r10", regs->r10);
	DICT_ADD_ULONG(regs_dict, "r9", regs->r9);
	DICT_ADD_ULONG(regs_dict, "r8", regs->r8);
	DICT_ADD_ULONG(regs_dict, "rax", regs->rax);
	DICT_ADD_ULONG(regs_dict, "rcx", regs->rcx);
	DICT_ADD_ULONG(regs_dict, "rdx", regs->rdx);
	DICT_ADD_ULONG(regs_dict, "rsi", regs->rsi);
	DICT_ADD_ULONG(regs_dict, "rdi", regs->rdi);
	DICT_ADD_ULONG(regs_dict, "orig_rax", regs->orig_rax);
	DICT_ADD_ULONG(regs_dict, "rip", regs->rip);
	DICT_ADD_ULONG(regs_dict, "cs", regs->cs);
	DICT_ADD_ULONG(regs_dict, "eflags", regs->eflags);
	DICT_ADD_ULONG(regs_dict, "rsp", regs->rsp);
	DICT_ADD_ULONG(regs_dict, "ss", regs->ss);
	DICT_ADD_ULONG(regs_dict, "fs_base", regs->fs_base);
	DICT_ADD_ULONG(regs_dict, "gs_base", regs->gs_base);
	DICT_ADD_ULONG(regs_dict, "ds", regs->ds);
	DICT_ADD_ULONG(regs_dict, "es", regs->es);
	DICT_ADD_ULONG(regs_dict, "fs", regs->fs);
	DICT_ADD_ULONG(regs_dict, "gs", regs->gs);
#undef DICT_ADD_ULONG

#else
	DICT_ADD_ULONG(regs_dict, "ebx", regs->ebx);	
	DICT_ADD_ULONG(regs_dict, "ecx", regs->ecx);
	DICT_ADD_ULONG(regs_dict, "edx", regs->edx);
	DICT_ADD_ULONG(regs_dict, "esi", regs->esi);
	DICT_ADD_ULONG(regs_dict, "edi", regs->edi);
	DICT_ADD_ULONG(regs_dict, "ebp", regs->ebp);
	DICT_ADD_ULONG(regs_dict, "eax", regs->eax);
	DICT_ADD_ULONG(regs_dict, "xds", regs->xds);
	DICT_ADD_ULONG(regs_dict, "xes", regs->xes);
	DICT_ADD_ULONG(regs_dict, "xfs", regs->xfs);
	DICT_ADD_ULONG(regs_dict, "xgs", regs->xgs);
	DICT_ADD_ULONG(regs_dict, "orig_eax", regs->orig_eax);
	DICT_ADD_ULONG(regs_dict, "eip", regs->eip);
	DICT_ADD_ULONG(regs_dict, "xcs", regs->xcs);
	DICT_ADD_ULONG(regs_dict, "eflags", regs->eflgas);
	DICT_ADD_ULONG(regs_dict, "esp", regs->esp);
	DICT_ADD_ULONG(regs_dict, "xss", regs->xss);
#endif
}

PyDoc_STRVAR(ptrace_getregs_doc, "copy the tracee's general-purpose");

static PyObject *
ptrace_getregs(PyObject *object, PyObject *args)
{
	pid_t pid;
	int ret;
	PyObject *regs_dict;
	struct user_regs_struct regs;
	
	if (!PyArg_ParseTuple(args, "I:getregs", &pid)) {
		return NULL;
	}
	ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	regs_dict = PyDict_New();
	/* copy registers*/
	add_regs_to_dict(regs_dict, &regs);
	return regs_dict; 
}



static inline void
add_fpregs_to_dict(PyObject *fpregs_dict, struct user_fpregs_struct *fpregs)
{ 
#ifndef __x86_64_

#define DICT_ADD_ULONG(x, y, z) PyDict_SetItemString(x, y, PyLong_FromUnsignedLong(z))
	DICT_ADD_ULONG(fpregs_dict, "cwd", fpregs->cwd);	
	DICT_ADD_ULONG(fpregs_dict, "swd", fpregs->swd);
	DICT_ADD_ULONG(fpregs_dict, "ftw", fpregs->ftw);
	DICT_ADD_ULONG(fpregs_dict, "fop", fpregs->fop);
	DICT_ADD_ULONG(fpregs_dict, "rip", fpregs->rip);
	DICT_ADD_ULONG(fpregs_dict, "rdp", fpregs->rdp);
	DICT_ADD_ULONG(fpregs_dict, "mxcsr", fpregs->mxcsr);
	DICT_ADD_ULONG(fpregs_dict, "mxcr_mask", fpregs->mxcr_mask); 

	/* for ST0-7 */
	PyDict_SetItemString(fpregs_dict, "st", PyString_FromStringAndSize((void *)fpregs->st_space, 128));
	/* for XMM-reg */
	PyDict_SetItemString(fpregs_dict, "xmm", PyString_FromStringAndSize((void *)fpregs->st_space, 256)); 
#undef DICT_ADD_ULONG

#else
	DICT_ADD_ULONG(fpregs_dict, "cwd", fpregs->cwd);
	DICT_ADD_ULONG(fpregs_dict, "swd", fpregs->swd);
	DICT_ADD_ULONG(fpregs_dict, "twd", fpregs->twd);
	DICT_ADD_ULONG(fpregs_dict, "fip", fpregs->fip);
	DICT_ADD_ULONG(fpregs_dict, "fcs", fpregs->fcs);
	DICT_ADD_ULONG(fpregs_dict, "foo", fpregs->foo);
	DICT_ADD_ULONG(fpregs_dict, "fos", fpregs->fos);
	/* for FP-register */
	PyDict_SetItemString(fpregs_dict, "st", PyString_FromStringAndSize(fpregs->st_space, 80)); 
#endif 
}


PyDoc_STRVAR(ptrace_getfpregs_doc, "copy the tracee's floating-point registers");

static PyObject *
ptrace_getfpregs(PyObject *object, PyObject *args)
{
	pid_t pid;
	int ret;
	PyObject *fpregs_dict;
	struct user_fpregs_struct fpregs;
	
	if (!PyArg_ParseTuple(args, "I:getfpregs", &pid)) {
		return NULL;
	} 
	ret = ptrace(PTRACE_GETREGS, pid, NULL, &fpregs);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	fpregs_dict = PyDict_New();
	add_fpregs_to_dict(fpregs_dict, &fpregs);
	return fpregs_dict; 
}


PyDoc_STRVAR(ptrace_getuser_doc, "copy the tracee's USER area, return as a dict");

static PyObject *
ptrace_getuser(PyObject *object, PyObject *args)
{
	pid_t pid;
	unsigned long ret;
	PyObject *user_dict;
	unsigned long *buffer;
	struct user *context;	
		
	if (!PyArg_ParseTuple(args, "I:getuser", &pid)) {
		return NULL;
	}

	unsigned ut = sizeof(struct user);
	buffer = PyMem_Malloc(ut + sizeof(unsigned long)); 

	unsigned t = ut / sizeof(unsigned long);

	if (ut % sizeof(unsigned long) > 0) {
		t += 1;	
	}
	unsigned i = 0;

	for(i = 0; i < t; i++) {
		ret = ptrace(PTRACE_PEEKUSER,
				pid,
				(void *)(i * sizeof(unsigned long)),
				NULL);
		if (ret < 0) {
			goto failed;	
		} 
		*(buffer + i) = ret;
	} 
	/* copy context */
	context = (void *)buffer;
	user_dict = PyDict_New();
	/* regs */
	PyObject *regs_dict = PyDict_New();
	add_regs_to_dict(regs_dict, &context->regs);
	PyDict_SetItemString(user_dict, "regs", regs_dict);
	/* u_fpvalid */
	PyDict_SetItemString(user_dict, "u_fpvalid", PyInt_FromLong(context->u_fpvalid));
	/* fpregs */
	PyObject *fpregs_dict = PyDict_New();
	add_fpregs_to_dict(fpregs_dict, &context->i387);
	PyDict_SetItemString(user_dict, "fpregs", fpregs_dict);
	/* tsize , dsize, usize*/	
	PyDict_SetItemString(user_dict, "tsize", PyLong_FromUnsignedLong(context->u_tsize));
	PyDict_SetItemString(user_dict, "dsize", PyLong_FromUnsignedLong(context->u_dsize));
	PyDict_SetItemString(user_dict, "ssize", PyLong_FromUnsignedLong(context->u_ssize));
	/* start_code, start_stack */
	PyDict_SetItemString(user_dict, "start_code", PyLong_FromUnsignedLong(context->start_code));
	PyDict_SetItemString(user_dict, "start_stack", PyLong_FromUnsignedLong(context->start_stack));
	/* signal */	
	PyDict_SetItemString(user_dict, "signal", PyLong_FromUnsignedLong(context->signal));
	/* magic */
	PyDict_SetItemString(user_dict, "magic", PyLong_FromUnsignedLong(context->magic));
	/* comm */
	PyDict_SetItemString(user_dict, "comm", PyString_FromString(context->u_comm));

	/* debug registers */
	PyObject *debugreg_tuple = PyTuple_New(8); 
	unsigned j;
	for(j = 0; j < 8; j++) {
#ifdef __x86_64_
		PyTuple_SetItem(debugreg_tuple, j, PyLong_FromUnsignedLong(context->u_debugreg[j]));
#else
		PyTuple_SetItem(debugreg_tuple, j, PyInt_FromLong(context->u_debugreg[j]));
#endif
	} 
	PyDict_SetItemString(user_dict, "debug_regs", debugreg_tuple); 
	PyMem_Free(buffer);
	return user_dict;
failed:
	PyMem_Free(buffer); 
	PyErr_SetFromErrno(PyExc_OSError);
	return NULL; 
}

static PyMethodDef ptrace_methods[] = {
	{"read_memory", (PyCFunction)ptrace_read_memory,
		METH_VARARGS, ptrace_read_memory_doc},
	{"write_memory", (PyCFunction)ptrace_write_memory,
		METH_VARARGS, ptrace_write_memory_doc}, 
	{"attach", (PyCFunction)ptrace_attach,
		METH_VARARGS, ptrace_attach_doc},
	{"detach", (PyCFunction)ptrace_detach,
		METH_VARARGS, ptrace_detach_doc},
	{"kill", (PyCFunction)ptrace_kill,
		METH_VARARGS, ptrace_kill_doc},
	{"cont", (PyCFunction)ptrace_cont,
		METH_VARARGS, ptrace_cont_doc},
	{"sysemu", (PyCFunction)ptrace_sysemu,
		METH_VARARGS, ptrace_sysemu_doc},
	{"sysemu_single", (PyCFunction)ptrace_sysemu_single,
		METH_VARARGS, ptrace_sysemu_single_doc},
	{"syscall", (PyCFunction)ptrace_syscall,
		METH_VARARGS, ptrace_syscall_doc},
	{"singlestep", (PyCFunction)ptrace_singlestep,
		METH_VARARGS, ptrace_singlestep_doc},
	{"getregs", (PyCFunction)ptrace_getregs,
		METH_VARARGS, ptrace_getregs_doc},
	{"getfpregs", (PyCFunction)ptrace_getfpregs,
		METH_VARARGS, ptrace_getfpregs_doc},
	{"getuser", (PyCFunction)ptrace_getuser,
		METH_VARARGS, ptrace_getuser_doc},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initptrace(void)
{	

	PyObject *m;
	m = Py_InitModule("ptrace", ptrace_methods);
	if (m == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "load ptrace failed"); 
	}
}
