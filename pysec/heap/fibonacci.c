#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "structmember.h"
#include "math.h"

typedef struct FH_node_t {
    PyObject*   key;
    PyObject*   value;

    struct FH_node_t*    parent;
    struct FH_node_t*    left;
    struct FH_node_t*    right;
    struct FH_node_t*    children;

    Py_ssize_t  degree;
    int         mark;

} FH_node;

void
FH_node_init(FH_node* node, PyObject* key, PyObject* value)
{
    node->key = key;
    node->value = value;
    node->parent = node->left = node->right = node->children = NULL;
    node->degree = 0;
    node->mark = 0;
}

typedef struct {
    PyObject_HEAD

    PyObject*   cmp;
    FH_node*    root_min;
    Py_ssize_t  size;
} FibonacciHeap;

#define FibonacciHeap_Check(obj) ((obj)->ob_type == &FibonacciHeapType)

static PyObject* FibonacciHeap_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(FibonacciHeap__doc__,
"Implementation of Fibonacci heap.");

static int
FibonacciHeap_init(FibonacciHeap *self, PyObject *args, PyObject *kwds)
{
    PyObject *cmp;
    
    static char *kwlist[] = {"cmp", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:FibonacciHeap", kwlist, 
                                        &cmp))
        return -1;
    
    if (!PyCallable_Check(cmp)) {
        PyErr_SetString(PyExc_TypeError, "cmp must be a callable object");
        return -1;
    }
    Py_INCREF(cmp);
    self->cmp = cmp;
    self->root_min = NULL;
    self->size = 0;
    return 0;
}

PyDoc_STRVAR(FibonacciHeap_insert__doc__,
"Insert an object with associated key.");

static PyObject*
FibonacciHeap_insert(FibonacciHeap *self, PyObject *args, PyObject *kwds)
{
    struct FH_node_t *new_node, *next;
    PyObject *key, *value, *pr_obj;
    int pr;

    static char *kwlist[] = {"key", "value", NULL};

    new_node = PyMem_New(struct FH_node_t, 1);
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:insert", kwlist, 
                                        &key, &value))
        return NULL;

    if (new_node == NULL)
        return PyErr_NoMemory();
    FH_node_init(new_node, key, value);
    
    if (self->root_min == NULL) {
        new_node->right = new_node->left = self->root_min = new_node;
    }
    else {
        pr_obj = PyObject_CallFunctionObjArgs(self->cmp, new_node->key, self->root_min->key, NULL);
        if (pr_obj == NULL) {
            PyMem_Free(new_node);
            return NULL;
        }
        pr = PyObject_IsTrue(pr_obj);
        if (pr == -1) {
            PyMem_Free(new_node);
            return NULL;
        }
        next = self->root_min->right;
        self->root_min->right = new_node;
        new_node->right = next;
        new_node->left = self->root_min;
        next->left = new_node;
        if (pr)
            self->root_min = new_node;
    }
    Py_INCREF(key);
    Py_INCREF(value);
    self->size++;
    return key;
}

PyDoc_STRVAR(FibonacciHeap_min__doc__,
"Return the object whose key is minimum.");

static PyObject*
FibonacciHeap_min(FibonacciHeap *self)
{
    if (self->root_min == NULL) {
        PyErr_SetString(PyExc_IndexError, "min from empty heap");
        return NULL;
    }
    Py_INCREF(self->root_min->value);
    return self->root_min->value;    
}

PyDoc_STRVAR(FibonacciHeap_extract__doc__,
"Remove and return the object from heap whose key is minimum.");

static int
FH_consolidate(FibonacciHeap *fh)
{
    FH_node *p, *f, *s, *tmp, *next;
    PyObject *pr_obj;
    int i, pr;
    int degree;
    
    degree = fh->size;
    
    FH_node *d2n[degree];
    
    for (i=0; i<degree; i++)
        d2n[i] = NULL;

    f = fh->root_min;
    do {
        next = f->right;
    
        while ((s = d2n[f->degree]) != NULL) {
            
            if (f == s)
                break;

            pr_obj = PyObject_CallFunctionObjArgs(fh->cmp, f->key, s->key, NULL);
            if (pr_obj == NULL)
                return -1;
            pr = PyObject_IsTrue(pr_obj);
            if (pr == -1)
                return -1;
            if (!pr) {
                tmp = f;
                f = s;
                s = tmp;
            }
            if (fh->root_min == s)
                fh->root_min = f;


            s->right->left = s->left;
            s->left->right = s->right;
            
            if (f->children == NULL) {
                f->children = s;
                s->right = s->left = s;
                s->parent = f;
            }
            else {
                tmp = f->children->right;
                f->children->right = s;
                s->left = f->children;
                s->right = tmp;
                tmp->left = s;
                s->parent = f;
            }
            if (next == s)
                next = f->right;
            d2n[f->degree] = NULL;
            f->degree++;
            s->mark = 1;
        }
        d2n[f->degree] = f;
        f = next;
    } while(f != fh->root_min);
    fh->root_min = NULL;

    for (i=0; i<degree; i++) {
        p = d2n[i];
        if (p != NULL) {
            if (fh->root_min == NULL) {
                p->left = p->right = p;
                fh->root_min = p;
            }
            else {
                tmp = fh->root_min->right;
                fh->root_min->right = p;
                p->left = fh->root_min;
                p->right = tmp;
                tmp->left = p;

                pr_obj = PyObject_CallFunctionObjArgs(fh->cmp, p->key, fh->root_min->key, NULL);
                if (pr_obj == NULL)
                    return -1;
                pr = PyObject_IsTrue(pr_obj);
                if (pr == -1)
                    return -1;
                if (pr)
                    fh->root_min = p;
            }
        }
    }
    
    return 0;
}


static PyObject*
FibonacciHeap_extract(FibonacciHeap *self)
{
    FH_node *child, *min, *next, *tmp;
    PyObject *value;
    
    min = self->root_min;
    if (min == NULL || !self->size) {
        PyErr_SetString(PyExc_IndexError, "extract from empty heap");
        return NULL;
    }
    
    
    child = min->children;
    if (child != NULL) {
        do {
            tmp = child->right;
            next = min->right;
            min->right = child;
            child->right = next;
            child->left = min;
            next->left = child;
            child->parent = NULL;

            child = tmp;
        } while(child != min->children);
    }

    /* remove min */
    if (min->right != min) {
        min->left->right = min->right;
        min->right->left = min->left;
        self->root_min = min->right;
    }
    else {
        self->root_min = NULL;
    }
    self->size--;

    if (self->root_min != NULL && self->root_min != self->root_min->right) {
        FH_consolidate(self);
    }

    /* save value */
    value = min->value;
    PyMem_Free(min);

    return value;
}

static Py_ssize_t
FibonacciHeap_len(PyObject *o)
{
    return ((FibonacciHeap *)o)->size;
}


static PySequenceMethods FibonacciHeap_sequence = {
    FibonacciHeap_len
};


static PyMethodDef FibonacciHeap_methods[] = {
    {"insert", (PyCFunction)FibonacciHeap_insert, METH_VARARGS, FibonacciHeap_insert__doc__},
    {"min", (PyCFunction)FibonacciHeap_min, METH_NOARGS, FibonacciHeap_min__doc__},
    {"extract", (PyCFunction)FibonacciHeap_extract, METH_NOARGS, FibonacciHeap_extract__doc__},
    { NULL }
};

static PyTypeObject FibonacciHeapType = {
    PyObject_HEAD_INIT(NULL)
    0,                              /* ob_size */
    "fibonacci.FibonacciHeap",      /* tp_name */
    sizeof(FibonacciHeap),          /* tp_basicsize */
    0,                              /* tp_itemsize */
    0,                              /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_compare */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    &FibonacciHeap_sequence,        /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
      Py_TPFLAGS_BASETYPE,          /* tp_flags */
    FibonacciHeap__doc__,           /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    FibonacciHeap_methods,          /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    (initproc)FibonacciHeap_init,   /* tp_init */
    0,                              /* tp_alloc */
    FibonacciHeap_new,              /* tp_new */
};


static PyObject*
FibonacciHeap_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    FibonacciHeap *fh;

    fh = (FibonacciHeap *)FibonacciHeapType.tp_alloc(&FibonacciHeapType, 0);
    return (PyObject *)fh;
}


static PyMethodDef fibonacci_methods[] = {
    { NULL }
};

PyDoc_STRVAR(fibonacci__doc__,
"Implementation of Fibonacci Heap.");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initfibonacci(void)
{
    PyObject *m;
    
    FibonacciHeapType.tp_new = FibonacciHeap_new;
    if (PyType_Ready(&FibonacciHeapType) < 0)
        return;

    m = Py_InitModule3("fibonacci", fibonacci_methods, fibonacci__doc__);

    if(m == NULL)
        return;

    Py_INCREF(&FibonacciHeapType);
    PyModule_AddObject(m, "FibonacciHeap", (PyObject *)&FibonacciHeapType);
}

