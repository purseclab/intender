#include <Python.h>
#include "bloom.h"

static PyObject *
bloom_wrapper(PyObject *self, PyObject *args)
{
    uint32_t *filter = malloc(4);
    uint64_t *dpid = malloc(8);
    uint32_t *port = malloc(4);

    // filter, ptr, size
    if (!PyArg_ParseTuple(args, "kKk", filter, dpid, port))
        return NULL;

    bloom_add_port(filter, *dpid, *port);
    uint32_t res = *filter;
    free(filter);
    free(dpid);
    free(port);

    return Py_BuildValue("k", res);
}

static PyMethodDef BloomMethods[] = {

    {"bloom",  bloom_wrapper, METH_VARARGS,
        "Calculate bloom filter."},

    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef bloommodule = {
    PyModuleDef_HEAD_INIT,
    "bloom",
    "Python interface for the bloom C function",
    -1,
    BloomMethods
};

PyMODINIT_FUNC PyInit_bloom(void) {
    return PyModule_Create(&bloommodule);
}

/*
DL_EXPORT(void) initbloom(void)
{
    Py_InitModule("bloom", BloomMethods);
}
*/
