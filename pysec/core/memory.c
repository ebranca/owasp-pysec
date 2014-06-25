/*
 * Python Security Project (PySec) and its related class files.
 *
 * PySec is a set of tools for secure application development under Linux
 *
 * Copyright 2014 PySec development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>


# define Memory_Check(obj) ((obj)->ob_type == &MemoryType)


typedef struct {
# ifndef S_SPLINT_S
    PyObject_HEAD;
#endif

    Py_ssize_t size;
    void *mem;
} MemoryObject;



PyDoc_STRVAR(memory__doc__,
"");


/*  Memory Type */

/*@null@*/ static PyObject* MemoryType__new__(PyTypeObject *, PyObject *, PyObject *);
static void MemoryType_dealloc(PyObject *);
/*@null@*/ static PyObject* MemoryType_set(PyObject *, PyObject *, PyObject *);
/*@null@*/ static PyObject* MemoryType_set_word(PyObject *, PyObject *, PyObject *);
/*@null@*/ static PyObject* MemoryType_get(PyObject *, PyObject *, PyObject *);
/*@null@*/ static PyObject* MemoryType_get_word(PyObject *, PyObject *, PyObject *);
/*@null@*/ static PyObject* MemoryType_find(PyObject *self, PyObject *args, PyObject *kwds);
/*@null@*/ static PyObject* MemoryType_str(PyObject *);
/*@null@*/ static PyObject* MemoryType_repr(PyObject *);
static Py_ssize_t MemoryType_len(PyObject *);
/*@null@*/ static PyObject* MemoryType_item(PyObject *, Py_ssize_t);
/*@null@*/ static PyObject* MemoryType_itemslice(PyObject *, Py_ssize_t, Py_ssize_t);
static int MemoryType_assitem(PyObject *, Py_ssize_t, PyObject *);
static int MemoryType_assslice(PyObject *, Py_ssize_t, Py_ssize_t, PyObject *);
static int MemoryType_contains(PyObject *, PyObject *);
/*@null@*/ static PyObject* MemoryType_read(PyObject *self, PyObject *args, PyObject *kwds);
/*@null@*/ static PyObject* MemoryType_write(PyObject *self, PyObject *args, PyObject *kwds);


static PyMemberDef MemoryType_members[] = {
    {"size", T_PYSSIZET, offsetof(MemoryObject, size), 0, "max size of the memory"},
    { NULL } /* sentinel */
};

static PySequenceMethods MemoryType_sequence = {
    MemoryType_len,
    0,
    0,
    MemoryType_item,
    MemoryType_itemslice,
    MemoryType_assitem,
    MemoryType_assslice,
    MemoryType_contains,
    0,
    0
};


static PyMethodDef MemoryType_methods[] = {
    {"set", (PyCFunction)MemoryType_set, METH_KEYWORDS, "TODO"},
    {"get", (PyCFunction)MemoryType_get, METH_KEYWORDS, "TODO"},
    {"set_word", (PyCFunction)MemoryType_set_word, METH_KEYWORDS, "TODO"},
    {"get_word", (PyCFunction)MemoryType_get_word, METH_KEYWORDS, "TODO"},
    {"find", (PyCFunction)MemoryType_find, METH_KEYWORDS, "TODO"},

    {"read", (PyCFunction)MemoryType_read, METH_KEYWORDS, "TODO"},
    {"write", (PyCFunction)MemoryType_write, METH_KEYWORDS, "TODO"},
    { NULL } /* sentinel */
};

PyDoc_STRVAR(memory_MemoryType__doc__,
"");

static PyTypeObject MemoryType = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "memory.Memory",            /*tp_name*/
    sizeof(MemoryObject),       /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    MemoryType_dealloc,         /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    MemoryType_repr,            /*tp_repr*/
    0,                          /*tp_as_number*/
    &MemoryType_sequence,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash */
    0,                          /*tp_call*/
    MemoryType_str,             /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,         /*tp_flags*/
    memory_MemoryType__doc__,       /* tp_doc */
    0,		                    /* tp_traverse */
    0,		                    /* tp_clear */
    0,		                    /* tp_richcompare */
    0,		                    /* tp_weaklistoffset */
    0,		                    /* tp_iter */
    0,		                    /* tp_iternext */
    MemoryType_methods,             /* tp_methods */
    MemoryType_members,             /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    MemoryType__new__,          /* tp_new */
};

/* API */

/*@null@*/
PyObject*
Memory_New(Py_ssize_t size, unsigned char b)
{
    MemoryObject *mem;
    unsigned char *mp;

    mem = (MemoryObject *)MemoryType.tp_alloc(&MemoryType, 0);
    if (mem == NULL)
        return NULL;

    mem->size = size;
    if ((mp = mem->mem = PyMem_MALLOC(mem->size)) == NULL)
        return PyErr_NoMemory();

    while (size--) {
        *mp = b;
        mp++;
    }

    return (PyObject *)mem;
}

int
Memory_set(MemoryObject *mem, Py_ssize_t n, uint8_t b)
{
    int old;
    uint8_t *mp;

    if (n >= mem->size || n < 0) {
        PyErr_Format(PyExc_IndexError, "index out of bounds, %zd", n);
        return -1;
    }
    mp = mem->mem + n;
    old = (uint8_t)(*mp);
    *mp = b;
    return old;
}

int
Memory_set_word(MemoryObject *mem, Py_ssize_t offset, void *word, Py_ssize_t len)
{
    Py_ssize_t end;

    end = offset + len;
    if (end > mem->size) {
        PyErr_Format(PyExc_IndexError, "range out of bounds, %zd:%zd", offset, end);
        return -1;
    }

    memmove(mem->mem + offset, word, len);

    return 0;
}

/*@null@*/
void *
Memory_get_word(MemoryObject *mem, Py_ssize_t offset, Py_ssize_t len)
{
    Py_ssize_t end;
    
    end = offset + len;
    if (end > mem->size) {
        PyErr_Format(PyExc_IndexError, "range out of bounds, %zd:%zd", offset, end);
        return NULL;
    }

    return mem->mem + offset;
}

int
Memory_get(MemoryObject *mem, Py_ssize_t n)
{
    if (n >= mem->size || n < 0) {
        PyErr_Format(PyExc_IndexError, "index out of bounds, %zd", n);
        return -1;
    }
    return *((uint8_t *)mem->mem + n);
}


Py_ssize_t
Memory_read_fd(int fd, Py_ssize_t size, MemoryObject *mem, Py_ssize_t offset)
{
    Py_ssize_t end;
    size_t b_read;

    end = size + offset;
    if (end > mem->size || end < 0) {
        PyErr_Format(PyExc_IndexError, "range out of bounds, %zd:%zd", offset, end);
        return -1;
    }
    if((int)(b_read = read(fd, mem->mem + offset, size)) < 0) {
        PyErr_SetFromErrno(PyExc_IOError);
        return -1;
    }
    return b_read;
}


Py_ssize_t
Memory_write_fd(int fd, MemoryObject *mem, Py_ssize_t offset, Py_ssize_t size)
{
    Py_ssize_t end;
    size_t b_write;

    end = size + offset;
    if (end > mem->size || end < 0) {
        PyErr_Format(PyExc_IndexError, "range out of bounds, %zd:%zd", offset, end);
        return -1;
    }
    if((b_write = write(fd, mem->mem + offset, size)) < 0)
        PyErr_SetFromErrno(PyExc_IOError);
    return b_write;
}




int
Memory_find(MemoryObject *mem, uint8_t* path, Py_ssize_t plen, Py_ssize_t start, Py_ssize_t end, Py_ssize_t* where)
{
	int *pi;
    uint8_t *src;
    Py_ssize_t slen, k = 0, q, i;

    src = mem->mem;
    slen = mem->size;
    if ((pi = PyMem_New(int, (unsigned int)plen)) == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    pi[0] = 0;
    for(q = 1; q < plen; q++) {
        while(k > 0 && path[k+1] != path[q])
            k = pi[k-1];
        if(path[k] == path[q])
            k++;
        pi[q] = k;
    }

    q = 0;
    for (i = start; i < slen; i++) {
        while (q > 0 && path[q] != src[i])
            q = pi[q-1];
        if (path[q] == src[i])
            q++;
        if (q == plen) {
            if (where != NULL)
                *where = i - plen + 1;
            return 1;
        }
    }
    return 0;
}

/* methods */

/*@null@*/
static PyObject*
MemoryType__new__(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    Py_ssize_t size;
    unsigned char fill = '\0';
    static char *kwlist[] = { "size", "fill", NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "n|b:Memory", kwlist, &size, &fill))
        return NULL;
    return Memory_New(size, fill);
}

static void
MemoryType_dealloc(PyObject* self)
{
    PyMem_Free(((MemoryObject *)(self))->mem);
}

/*@null@*/
static PyObject*
MemoryType_str(PyObject *self)
{
    Py_ssize_t len;
    PyObject *str;
    char *sp;
    unsigned char *mp;

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    len = ((MemoryObject *)self)->size;
    str = PyString_FromStringAndSize(NULL, len);
    if (str == NULL)
        return NULL;
    mp = ((MemoryObject *)self)->mem;
    sp = PyString_AS_STRING(str);

    while (len--) {
        *sp = *mp++;
        sp++;
    }
    return str;
}

/*@null@*/
static PyObject*
MemoryType_repr(PyObject *self)
{
    Py_ssize_t len;
    PyObject *str;
    char *sp;
    unsigned char *mp;

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    len = ((MemoryObject *)self)->size;
    str = PyString_FromStringAndSize(NULL, len);
    if (str == NULL)
        return NULL;
    mp = ((MemoryObject *)self)->mem;
    sp = PyString_AS_STRING(str);

    while (len--) {
        *sp = *mp++;
        sp++;
    }
    return PyObject_Repr(str);
}

/*@null@*/
static PyObject* 
MemoryType_set(PyObject *self, PyObject *args, PyObject *kwds)
{
    Py_ssize_t n;
    unsigned char b;
    int old;
    static char *kwlist[] = {"n", "b", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "n:set", kwlist, &n, &b))
        return NULL;
    old = Memory_set((MemoryObject *)self, n, b);
    if (old < 0)
        return NULL;
    else
        return PyInt_FromLong(old);
}

/*@null@*/
static PyObject* 
MemoryType_set_word(PyObject *self, PyObject *args, PyObject *kwds)
{
    void *word;
    int wlen;
    Py_ssize_t offset = 0;
    static char *kwlist[] = {"word", "offset", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    /* TODO - add set by memory */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#|n:set_word", kwlist, &word, &wlen, &offset))
        return NULL;

    if (Memory_set_word((MemoryObject *)self, offset, word, wlen) < 0)
        return NULL;

    Py_INCREF(self);
    return self;
}

/*@null@*/
static PyObject*
MemoryType_find(PyObject *self, PyObject *args, PyObject *kwds)
{
    void *path;
    Py_ssize_t plen, start, end, where;
    static char *kwlist[] = {"path", "start", "end", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#|nn:find", kwlist, &path, &plen, &start, &end))
        return NULL;

    switch (Memory_find((MemoryObject *)self, path, plen, start, end, &where))
    {
        case -1:    return NULL;
        case 0:     Py_RETURN_NONE;
        case 1:
        default:    return PyLong_FromSsize_t(where);
    }
}

/*@null@*/
static PyObject* 
MemoryType_get(PyObject *self, PyObject *args, PyObject *kwds)
{
    Py_ssize_t n;
    int b;
    static char *kwlist[] = {"n", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "n:get", kwlist, &n))
        return NULL;
    b = Memory_get((MemoryObject *)self, n);
    if (b < 0)
        return NULL;
    else
        return PyInt_FromLong(b);
}

/*@null@*/
static PyObject* 
MemoryType_get_word(PyObject *self, PyObject *args, PyObject *kwds)
{
    Py_ssize_t offset, len;
    void *word;
    static char *kwlist[] = {"offset", "len", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "nn:get_word", kwlist, &offset, &len))
        return NULL;
    if (len < 0)
        len = ((MemoryObject *)self)->size - offset;
    word = Memory_get_word((MemoryObject *)self, offset, len);
    if (word == NULL)
        return NULL;
    else
        return PyString_FromStringAndSize(word, len);
}

static Py_ssize_t
MemoryType_len(PyObject *o)
{
    if (!Memory_Check(o)) {
        PyErr_BadArgument();
        return -1;
    }
    return ((MemoryObject *)o)->size;
}


static int
MemoryType_contains(PyObject *o1, PyObject *o2)
{
    void *path;
    Py_ssize_t plen;
    if (!Memory_Check(o1)) {
        PyErr_BadArgument();
        return -1;
    }
    if (PyString_Check(o2)) {
        path = PyString_AS_STRING(o2);
        plen = PyString_Size(o2);
    }
    else if (Memory_Check(o2)) {
        path = ((MemoryObject *)o1)->mem;
        plen = ((MemoryObject *)o1)->size;
    }
    else {
        PyErr_SetString(PyExc_TypeError, "can sarch only Memory objects or strings inside Memory object");
        return -1;
    }
    switch(Memory_find((MemoryObject *)o1, path, plen, 0, ((MemoryObject *)o1)->size, NULL))
    {
        case -1:    return -1;
        case 0:     return 0;
        case 1:
        default:    return 1;
    }
}

/*@null@*/
static PyObject*
MemoryType_read(PyObject *self, PyObject *args, PyObject *kwds)
{
    int fd;
    Py_ssize_t offset, len;
    static char *kwlist[] = {"fd", "offset", "len", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "inn:read", kwlist, &fd, &offset, &len))
        return NULL;
    len = Memory_read_fd(fd, len, (MemoryObject *)self, offset);
    if (len == -1)
        return NULL;
    return PyInt_FromSsize_t(len);
}

/*@null@*/
static PyObject*
MemoryType_write(PyObject *self, PyObject *args, PyObject *kwds) {
    int fd;
    Py_ssize_t offset, len;
    static char *kwlist[] = {"fd", "offset", "len", NULL};

    if (!Memory_Check(self)) {
        PyErr_BadArgument();
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "inn:read", kwlist, &fd, &offset, &len))
        return NULL;
    len = Memory_write_fd(fd, (MemoryObject *)self, offset, len);
    if (len == -1)
        return NULL;
    return PyInt_FromSsize_t(len);
}

/* sequence methods */

/*@null@*/
static PyObject*
MemoryType_item(PyObject *o, Py_ssize_t i) {
    int b;

    if (!Memory_Check(o)) {
        PyErr_BadArgument();
        return NULL;
    }

    if((b = Memory_get((MemoryObject *)o, i)) < 0)
        return NULL;
    return PyInt_FromLong(b);
}


static int
MemoryType_assitem(PyObject *o, Py_ssize_t i, PyObject *v)
{
    PyObject *tmp;
    long val;
    if (!Memory_Check(o)) {
        PyErr_BadArgument();
        return -1;
    }

    if (PyString_Check(v)) {
        if (PyString_Size(v) != 1) {
            PyErr_SetString(PyExc_ValueError, "memory value can be only 1-char string");
            return -1;
        }
        if (Memory_set((MemoryObject *)o, i, PyString_AS_STRING(v)[0]) < 0)
            return -1;
    }
    else if (PyNumber_Check(v)) {
        tmp = PyNumber_Int(v);
        if (tmp == NULL)
            return -1;
        val = PyInt_AsLong(tmp);
        if (val == -1 && PyErr_Occurred())
            return -1;
        if (val < 0 || val > 255) {
            PyErr_Format(PyExc_IndexError, "index out of bounds, %ld", val);
            return -1;
        }
    }
    else {
        PyErr_SetString(PyExc_TypeError, "value must be a 1-char string or a 1-byte integer");
        return -1;
    }
    return 0;
}

/*@null@*/
static PyObject*
MemoryType_itemslice(PyObject *o, Py_ssize_t a, Py_ssize_t b)
{
    void *slice;
    Py_ssize_t len;
    if (!Memory_Check(o)) {
        PyErr_BadArgument();
        return NULL;
    }
    len = b - a;
    slice = Memory_get_word((MemoryObject *)o, a, len);
    if (slice == NULL)
        return NULL;
    return PyString_FromStringAndSize(slice, len);
}


int
MemoryType_assslice(PyObject *o, Py_ssize_t a, Py_ssize_t b, PyObject* v)
{
    Py_ssize_t len;
    if (!Memory_Check(o)) {
        PyErr_BadArgument();
        return -1;
    }

    len = b - a;
    if (PyString_Check(v)) {
        if (PyString_Size(v) != len) {
            PyErr_SetString(PyExc_ValueError, "value length and slice length are different");
            return -1;
        }
        if (Memory_set_word((MemoryObject *)o, a, PyString_AS_STRING(v), len))
            return -1;
    }
    else {
        PyErr_SetString(PyExc_TypeError, "value must be a string");
        return -1;
    }
    return 0;
}

/*
int tp_print(MemoryObject* self, FILE *file, int flags)
{
    if (flags & Py_PRINT_RAW)
        fwrite(self->mem, sizeof void, self->size, file);
    else
        return -1;
}
*/

static PyMethodDef memory_methods[] = {
    { NULL } /* sentinel */
};


#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initmemory(void)
{
    PyObject *m;

    MemoryType.tp_new = MemoryType__new__;
    if (PyType_Ready(&MemoryType) < 0)
        return;

    m = Py_InitModule3("memory", memory_methods, memory__doc__);
    if(m == NULL)
        return;

    Py_INCREF(&MemoryType);
    PyModule_AddObject(m, "Memory", (PyObject *)&MemoryType);
}
