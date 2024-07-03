
/* 

   This is an emacs25 module providing an elisp interface into the libcapstone 
   disassembly engine (http://www.capstone-engine.org). Hopefully you'll find
   use for it in your travels.

   - bas@mokusatsu.org 09/04/2016

*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <emacs-module.h>
/* see this for C api documentation */
#include <capstone.h>

int plugin_is_GPL_compatible;

/* memory management*/
#define _CS_GREF(a)      env->make_global_ref(env, a)
#define _CS_FREE_GREF(g) env->free_global_ref(env, g)

/* function registration */
#define _CS_INTERN(s) env->intern(env, s)
#define _CS_FUNC(min, max, c_func, doc, data) env->make_function(env, min, max, c_func, doc, data)
/* this requires static arrays */
#define _CS_FUNCALL(func, args)                         \
    ({                                                  \
        env->funcall(env, env->intern(env, func),       \
                     sizeof(args)/sizeof(emacs_value),  \
                     args);                             \
    })

/* nil */
#define _CS_NIL() _CS_INTERN("nil")

/* type conversions */
#define _CS_TYPE(val)                  env->type_of(env, val)
#define _CS_NOT_NIL(val)               env->is_not_nil(env, val)
#define _CS_EQ(a, b)                   env->eq(env, a, b)
#define _CS_INT(val)                   env->make_integer(env, val)
#define _CS_PULL_INT(val)              env->extract_integer(env, val)
#define _CS_FLOAT(val)                 env->make_float(env, val)
#define _CS_PULL_FLOAT(val)            env->extract_float(env, val)
#define _CS_STRING(s, len)             env->make_string(env, s, len)
#define _CS_UNIBYTE_STRING(s, len)     env->make_unibyte_string(env, s, len)
#define _CS_PULL_STRING(src, dst, len) env->copy_string_contents(env, src, dst, len)
/* #define _CS_PULL_STRING_SIZE(src)                        \ */
/*     ({                                                   \ */
/*         ptrdiff_t len;                                   \ */
/*         env->copy_string_contents(env, src, NULL, &len); \ */
/*         len;                                             \ */
/*     }) */
#define _CS_PULL_UNIBYTE_STRING(src, dst, len) env->copy_unibyte_string_contents(env, src, dst, len)

/* vector functions */
#define _CS_VEC_SIZE(vec)              env->vec_size(env, vec)
#define _CS_VEC_GET(vec, i)            env->vec_get(env, vec, i)
#define _CS_VEC_SET(vec, i, val)       env->vec_set(env, vec, i, val)

/* embedded pointers */
#define _CS_UPTR(fin, ptr)             env->make_user_ptr(env, fin, ptr)
#define _CS_UPTR_GET(uptr)             env->get_user_ptr(env, uptr)
#define _CS_UPTR_SET(uptr, ptr)        env->set_user_ptr(env, uptr, ptr)
#define _CS_UFIN_GET(uptr)             env->get_user_finalizer(env, uptr)
#define _CS_UFIN_SET(uptr, fin)        env->set_user_finalizer(env, uptr, fin)

/* errors */
#define _CS_SIGNAL(err, data)          env->non_local_exit_signal(env, _CS_INTERN(err), data)

/* utilities */
#define _CS_MIN(a,b) (((a)<(b))?(a):(b))

#define READELF_MAX_PATH_SIZE 1024
#define READELF_MAX_CSTR_SIZE 1048576

typedef struct {
    FILE *f;
} elf_file;

static void
elf_file_finalizer(void *obj)
{
    elf_file *ef = (elf_file *)obj;
    if (ef && ef->f)
        fclose(ef->f);
    free(ef);
}

// XXX[btv] - expose
static emacs_value
Fcall_re_fopen(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    char buf[READELF_MAX_PATH_SIZE];
    ptrdiff_t len = READELF_MAX_PATH_SIZE;

    bool success = _CS_PULL_STRING(args[0], buf, &len);
    // TODO[btv] give a better error message for too long paths?
    if (!success)
        return _CS_NIL();

    FILE *f = fopen(buf, "r");
    if (!f) {
        emacs_value error_data = _CS_INT(errno);
        // XXX[btv] define this
        _CS_SIGNAL("readelf-fopen-failed", error_data);
        return _CS_NIL();
    }
    elf_file *ef = malloc(sizeof(*ef));
    if (!ef) {
        // XXX[btv] define this
        _CS_SIGNAL("readelf-oom", _CS_NIL());
        return _CS_NIL();
    }
    ef->f = f;
    return _CS_UPTR(elf_file_finalizer, ef);
}

typedef struct {
    char *buf;
    size_t sz;
} re_bytes;

static void
re_bytes_finalizer(void *obj)
{
    re_bytes *p_bytes = (re_bytes *)obj;
    if (p_bytes && p_bytes->buf)
        free(p_bytes->buf);
    free(p_bytes);
}

static re_bytes
read_inner(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    elf_file *ef = (elf_file *)_CS_UPTR_GET(args[0]);
    size_t seek_val = _CS_PULL_INT(args[1]);
    // XXX[btv] do error handling/bounds checking. In lisp?
    size_t sz = _CS_PULL_INT(args[2]);

    char *buf = malloc(sz);
    if (!buf) {
        _CS_SIGNAL("readelf-oom", _CS_NIL());
        return (re_bytes) { NULL, 0 };
    }
    int ret = fseek(ef->f, seek_val, SEEK_SET);
    if (ret) {
        emacs_value error_data = _CS_INT(errno);
        free(buf);
        // XXX[btv] define this
        _CS_SIGNAL("readelf-fseek-failed", error_data);
        return (re_bytes) { NULL, 0 };
    }
    size_t nread = fread(buf, 1, sz, ef->f);
    if (nread != sz) {        
        emacs_value error_data = _CS_INT(nread);
        free(buf);
        _CS_SIGNAL("readelf-fread-failed", error_data);
        return (re_bytes) { NULL, 0 };
    }
    return (re_bytes) { buf, sz };
}

static emacs_value
Fcall_re_fread(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    re_bytes bytes = read_inner(env, nargs, args, data);
    if (!bytes.buf)
        return _CS_NIL();
    return _CS_UNIBYTE_STRING(bytes.buf, bytes.sz);
}

static emacs_value
Fcall_re_fread_to_code(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    re_bytes bytes = read_inner(env, nargs, args, data);
    if (!bytes.buf)
        return _CS_NIL();
    re_bytes *p_bytes = malloc(sizeof(*p_bytes));
    if (!p_bytes) {
        // XXX[btv] define this
        _CS_SIGNAL("readelf-oom", _CS_NIL());
        return _CS_NIL();
    }
    memcpy(p_bytes, &bytes, sizeof(bytes));
    
    return _CS_UPTR(re_bytes_finalizer, p_bytes);    
}

static emacs_value
Fcall_re_cstr(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
    
{
    size_t capacity = 1024;
    size_t len = 0;
    size_t p = 0;
    char *buf = malloc(capacity);
    if (!buf) {
        _CS_SIGNAL("readelf-oom", _CS_NIL());
        return _CS_NIL();
    }
    
    // XXX[btv] type checking for this and all other uptr reads?
    elf_file *ef = (elf_file *)_CS_UPTR_GET(args[0]);
    size_t seek_val = _CS_PULL_INT(args[1]);
    assert(ef && ef->f);
    int ret = fseek(ef->f, seek_val, SEEK_SET);
    if (ret) {
        emacs_value error_data = _CS_INT(errno);
        free(buf);
        // XXX[btv] define this
        _CS_SIGNAL("readelf-fseek-failed", error_data);
        return _CS_NIL();
    }

    size_t max = READELF_MAX_CSTR_SIZE - 1;
    if (nargs > 2) {
        size_t user_max = _CS_PULL_INT(args[2]);
        if (user_max < max)
            max = user_max;
    }
    size_t rem = max + 1;
    while (rem) {
        if (p == len) {
            if (len == capacity) {
                capacity *= 2;
                char *new_buf = realloc(buf, capacity);
                if (!new_buf) {
                    free(buf);
                    _CS_SIGNAL("readelf-oom", _CS_NIL());
                    return _CS_NIL();
                }
                buf = new_buf;
            }
            size_t sz = _CS_MIN(capacity - len, _CS_MIN(rem, 1024));
            assert(sz);
            size_t nread = fread(buf + len, 1, sz, ef->f);
            if (!nread) {
                free(buf);
                _CS_SIGNAL("readelf-overflow", _CS_NIL());
                return _CS_NIL();
            }
            len += nread;            
        }
        if (!buf[p]) {
            break;
        }
        ++p;
        --rem;
    }
    if (p < len && !buf[p]) {
        emacs_value retval = _CS_UNIBYTE_STRING(buf, p);
        free(buf);
        return retval;
    }
    free(buf);
    _CS_SIGNAL("readelf-overflow", _CS_NIL());
    return _CS_NIL();
}
static emacs_value
Fcall_re_code_len(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    re_bytes *bytes = (re_bytes *)_CS_UPTR_GET(args[0]);
    assert(bytes);
    return _CS_INT(bytes->sz);
}

static emacs_value
Fcall_re_code_substr(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    re_bytes *code = (re_bytes *)_CS_UPTR_GET(args[0]);
    assert(code);
    size_t start = _CS_PULL_INT(args[1]);
    size_t len = _CS_PULL_INT(args[2]);

    if ((len && (start > code->sz)) || (len > (code->sz - start))) {
        return _CS_UNIBYTE_STRING(NULL, 0);            
    }

    return _CS_UNIBYTE_STRING(code->buf + start, len);
}


static emacs_value
Fcall_cs_version(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    unsigned int ret = cs_version(NULL, NULL); 
    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_support(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    bool ret;
    int query = (int)_CS_PULL_INT(args[0]);
    
    ret = cs_support(query);
    
    return _CS_INT(ret);
}

static emacs_value
Fcall_cs_open(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret = CS_ERR_OK;
    cs_arch arch = (cs_arch)_CS_PULL_INT(args[0]); 
    cs_mode mode = (cs_mode)_CS_PULL_INT(args[1]); 
    csh handle = 0;

    // TODO[btv] - Finalizer?
    ret = cs_open(arch, mode, &handle);

    /* return the handle on success, nil on failure */
    if (ret == CS_ERR_OK) {
        return _CS_INT(handle);
    } else {
        /* explicitly check all error values before accepting ret as handle */
        return _CS_INT(ret);
    }
}

static emacs_value
Fcall_cs_close(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);

    ret = cs_close(&handle);

    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_option(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    cs_opt_type type = (cs_opt_type)_CS_PULL_INT(args[1]);
    size_t value = (size_t)_CS_PULL_INT(args[2]);

    ret = cs_option(handle, type, value);

    return _CS_INT(ret);
}

static emacs_value
Fcall_cs_errno(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    cs_err ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);

    ret = cs_errno(handle);

    return _CS_INT(ret); 
}

static emacs_value
Fcall_cs_strerror(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    cs_err code = (cs_err)_CS_PULL_INT(args[0]);

    ret = cs_strerror(code);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    }
    else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_reg_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int reg_id = (unsigned int)_CS_PULL_INT(args[1]);

    ret = cs_reg_name(handle, reg_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_insn_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int insn_id = (unsigned int)_CS_PULL_INT(args[1]);
    
    ret = cs_insn_name(handle, insn_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

static emacs_value
Fcall_cs_group_name(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    const char *ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    unsigned int group_id = (unsigned int)_CS_PULL_INT(args[1]);
    
    ret = cs_group_name(handle, group_id);
    if (ret != NULL) {
        return _CS_STRING(ret, strlen(ret));
    } else {
        return _CS_NIL();
    }
}

typedef struct {
    cs_insn *insns;
    size_t n;
} re_insn_block;

void re_insn_block_finalizer(void *obj) {
    re_insn_block *reib = (re_insn_block *)obj;
    assert(reib && reib->insns);
    cs_free(reib->insns, reib->n);
    free(reib);
}

static emacs_value
Fcall_cs_disasm(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    size_t ret;
    csh handle = (csh)_CS_PULL_INT(args[0]);
    const re_bytes *code = _CS_UPTR_GET(args[1]);
    size_t start = (size_t)_CS_PULL_INT(args[2]);
    size_t len = (size_t)_CS_PULL_INT(args[3]);
    uint64_t address = (uint64_t)_CS_PULL_INT(args[4]);
    size_t count = (size_t)_CS_PULL_INT(args[5]);
    cs_insn *insn; 

    if (len && (start > code->sz)) {
        emacs_value err_data_args[3];
        err_data_args[0] = args[1];
        err_data_args[1] = _CS_INT(start);
        err_data_args[2] = _CS_INT(len);
        _CS_SIGNAL("args-out-of-range", _CS_FUNCALL("list", err_data_args));
        return _CS_NIL();
    }

    if (len > (code->sz - start)) {
        emacs_value err_data_args[3];
        err_data_args[0] = args[1];
        err_data_args[1] = _CS_INT(start);
        err_data_args[2] = _CS_INT(len);
        _CS_SIGNAL("args-out-of-range", _CS_FUNCALL("list", err_data_args));
        return _CS_NIL();
    }
        
    ret = cs_disasm(handle, (uint8_t*)code->buf + start, len, address, count, &insn); 
    
    if (ret == 0) {
        /* cs_errno() available */ 
        return _CS_NIL();
    }

    re_insn_block *reib = malloc(sizeof(*reib));
    if (!reib) {
        _CS_SIGNAL("readelf-oom", _CS_NIL());
        return _CS_NIL();
    }
    reib->insns = insn;
    reib->n = ret;

    return _CS_UPTR(re_insn_block_finalizer, reib);

    /* // (make-vector ret nil) */
    /* emacs_value vector_args[2]; */
    /* vector_args[0] = _CS_INT(ret); */
    /* vector_args[1] = _CS_NIL(); */

    /* emacs_value id_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value addr_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value size_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value bytes_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value mnemonic_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value op_str_vec = _CS_FUNCALL("make-vector", vector_args); */
    /* emacs_value opcodes_vec = _CS_FUNCALL("make-vector", vector_args); */

    /* // TODO[btv] - Profile disasm. Can it be made faster? */
    /* // Or should we port more stuff from lisp to C? */
    /* for (int i = 0; i < ret; ++i) { */
    /*     _CS_VEC_SET(id_vec, i, _CS_INT(insn[i].id)); */
    /*     _CS_VEC_SET(addr_vec, i, _CS_INT(insn[i].address)); */
    /*     _CS_VEC_SET(size_vec, i, _CS_INT(insn[i].size)); */
    /*     _CS_VEC_SET(bytes_vec, i, _CS_UNIBYTE_STRING((char *)insn[i].bytes, insn[i].size)); */
    /*     _CS_VEC_SET(mnemonic_vec, i, _CS_STRING(insn[i].mnemonic, strlen(insn[i].mnemonic))); */
    /*     _CS_VEC_SET(op_str_vec, i, _CS_STRING(insn[i].op_str, strlen(insn[i].op_str))); */
    /*     // XXX[btv] - Support other arches and also */
    /*     // check to make sure detail is on and skipdata is off. */
    /*     // */
    /*     // This probably requires us to interpose calls to cs_open and cs_option to */
    /*     // track this. */
    /*     if (insn[i].detail) { */
    /*         emacs_value vector_args[2]; */
    /*         vector_args[0] = _CS_INT(insn[i].detail->arm64.op_count); */
    /*         vector_args[1] = _CS_NIL(); */
    /*         emacs_value ops_vec = _CS_FUNCALL("make-vector", vector_args); */
    /*         for (int x = 0; x < insn[i].detail->arm64.op_count; ++x) { */
    /*             cs_arm64_op *op = &insn[i].detail->arm64.operands[x];            */

    /*             emacs_value op_list; */
    /*             // TODO[btv] use something faster than lists here. */
    /*             switch (op->type) { */
    /*             case ARM64_OP_REG: { */
    /*                 emacs_value list_args[2]; */
    /*                 list_args[0] = _CS_INTERN("reg"); */
    /*                 // TODO[btv] symbolic register names */
    /*                 list_args[1] = _CS_INT(op->reg); */
    /*                 op_list = _CS_FUNCALL("vector", list_args); */
    /*             } */
    /*                 break; */
    /*             case ARM64_OP_IMM: { */
    /*                 emacs_value list_args[2]; */
    /*                 list_args[0] = _CS_INTERN("imm"); */
    /*                 list_args[1] = _CS_INT(op->imm); */
    /*                 op_list = _CS_FUNCALL("vector", list_args); */
    /*             } */
    /*                 break; */
    /*             case ARM64_OP_MEM: { */
    /*                 emacs_value list_args[4]; */
    /*                 list_args[0] = _CS_INTERN("mem"); */
    /*                 list_args[1] = _CS_INT(op->mem.base); */
    /*                 list_args[2] = _CS_INT(op->mem.index); */
    /*                 list_args[3] = _CS_INT(op->mem.disp); */
    /*                 op_list = _CS_FUNCALL("vector", list_args); */
    /*             } */
    /*                 break; */
    /*             default: */
    /*                 op_list = _CS_NIL(); */
    /*             } */

    /*             _CS_VEC_SET(ops_vec, x, op_list); */
    /*         } */
    /*         _CS_VEC_SET(opcodes_vec, i, ops_vec); */
    /*     } */
    /* } */

    /* /\* we're done at the native layer with this stuff, so free it *\/ */
    /* cs_free(insn, ret); */
    
    /* emacs_value list_args[7]; */
    /* list_args[0] = id_vec; */
    /* list_args[1] = addr_vec; */
    /* list_args[2] = size_vec; */
    /* list_args[3] = bytes_vec; */
    /* list_args[4] = mnemonic_vec; */
    /* list_args[5] = op_str_vec; */
    /* list_args[6] = opcodes_vec;         */
    
    /* return _CS_FUNCALL("list", list_args); */
}

static emacs_value
Fcall_re_foreach_insn(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
    re_insn_block *reib = _CS_UPTR_GET(args[1]);
    emacs_value f = args[0];

    for (size_t i = 0; i < reib->n; ++i) {
        cs_insn *insn = &reib->insns[i];
        emacs_value id = _CS_INT(insn->id);
        emacs_value addr = _CS_INT(insn->address);
        emacs_value size = _CS_INT(insn->size);
        emacs_value bytes = _CS_UNIBYTE_STRING((char *)insn->bytes, insn->size);
        emacs_value mnemonic = _CS_STRING(insn->mnemonic, strlen(insn->mnemonic));
        emacs_value op_str = _CS_STRING(insn->op_str, strlen(insn->op_str));
        emacs_value ops_vec = _CS_NIL();
        if (insn->detail) {
            emacs_value vector_args[2];
            vector_args[0] = _CS_INT(insn->detail->arm64.op_count);
            vector_args[1] = _CS_NIL();
            ops_vec = _CS_FUNCALL("make-vector", vector_args);
            for (int x = 0; x < insn->detail->arm64.op_count; ++x) {
                cs_arm64_op *op = &insn->detail->arm64.operands[x];

                emacs_value op_list;
                switch (op->type) {
                case ARM64_OP_REG: {
                    emacs_value list_args[2];
                    list_args[0] = _CS_INTERN("reg");
                    // TODO[btv] symbolic register names
                    list_args[1] = _CS_INT(op->reg);
                    op_list = _CS_FUNCALL("vector", list_args);
                }
                    break;
                case ARM64_OP_IMM: {
                    emacs_value list_args[2];
                    list_args[0] = _CS_INTERN("imm");
                    list_args[1] = _CS_INT(op->imm);
                    op_list = _CS_FUNCALL("vector", list_args);
                }
                    break;
                case ARM64_OP_MEM: {
                    emacs_value list_args[4];
                    list_args[0] = _CS_INTERN("mem");
                    list_args[1] = _CS_INT(op->mem.base);
                    list_args[2] = _CS_INT(op->mem.index);
                    list_args[3] = _CS_INT(op->mem.disp);
                    op_list = _CS_FUNCALL("vector", list_args);
                }
                    break;
                default:
                    op_list = _CS_NIL();
                }

                _CS_VEC_SET(ops_vec, x, op_list);
            }
        }
        emacs_value list_args[7] = {id, addr, size, bytes, mnemonic, op_str, ops_vec};
        emacs_value list = _CS_FUNCALL("list", list_args);
        env->funcall(env, f, 1, &list);
    }
    return _CS_NIL();
}


/* bind c_func (native) to e_func (elisp) */
static void
bind(emacs_env *env, emacs_value (*c_func) (emacs_env *env,
                                            ptrdiff_t nargs,
                                            emacs_value args[],
                                            void *) EMACS_NOEXCEPT,
     const char *e_func,
     ptrdiff_t min_arity,
     ptrdiff_t max_arity,
     const char *doc,
     void *data)
{
    emacs_value fset_args[2];
    
    fset_args[0] = _CS_INTERN(e_func);
    fset_args[1] = _CS_FUNC(min_arity, max_arity, c_func, doc, data);
    _CS_FUNCALL("fset", fset_args);
}

int
emacs_module_init(struct emacs_runtime *ert)
{
    emacs_env *env = ert->get_environment(ert); 
    
    bind(env,
        Fcall_cs_version, "capstone--cs-version", 0, 0, 
        "Return combined cs api version",
        NULL); 
    
    bind(env,
        Fcall_cs_support, "capstone--cs-support", 1, 1, 
        "Check cs for enabled support of ARCH",
        NULL); 
    
    bind(env,
        Fcall_cs_open, "capstone--cs-open", 2, 2, 
        "Initialize cs handle to ARCH and MODE",
        NULL);

    bind(env,
        Fcall_cs_close, "capstone--cs-close", 1, 1, 
        "Close cs handle (careful, frees internals)",
        NULL);

    bind(env,
        Fcall_cs_option, "capstone--cs-option", 3, 3, 
        "Set option on cs HANDLE of TYPE and VALUE",
        NULL); 
   
    bind(env,
        Fcall_cs_errno, "capstone--cs-errno", 1, 1, 
        "Report the last cs error from HANDLE",
        NULL); 

    bind(env,
        Fcall_cs_strerror, "capstone--cs-strerror", 1, 1, 
        "Return a string describing given error CODE",
        NULL); 

    bind(env,
        Fcall_cs_reg_name, "capstone--cs-reg-name", 2, 2, 
        "Using cs HANDLE return string name of REGISTER_ID",
        NULL); 
    
    bind(env,
        Fcall_cs_insn_name ,"capstone--cs-insn-name", 2, 2, 
        "Using cs HANDLE return string name of INSN_ID",
        NULL); 
    
    bind(env,
        Fcall_cs_group_name, "capstone--cs-group-name", 2, 2,
        "Using cs HANDLE return string name of GROUP_ID",
        NULL); 
    
    bind(env,
         Fcall_cs_disasm, "capstone--cs-disasm", 6, 6,
        "Using cs HANDLE disassemble CODE object from START for LEN bytes labeled as starting at ADDRESS for COUNT number of instructions (0 for all), returning insn block",
        NULL);

    bind(env,
         Fcall_re_fread, "readelf--fread", 3, 3,
         "Read from ELF-FILE at START SIZE bytes and return a unibyte string",
         NULL);

    bind(env,
         Fcall_re_fread_to_code, "readelf--fread-to-code", 3, 3,
         "Read from ELF-FILE at START SIZE bytes and return an opaque code object for use with `capstone--cs-disasm'",
         NULL);
    bind(env,
         Fcall_re_fopen, "readelf--fopen", 1, 1,
         "Open FILENAME as an elf file",
         NULL);
    bind(env,
         Fcall_re_cstr, "readelf--cstr", 2, 3,
         "Read a C string from ELF-FILE at START, optionally of max size MAX, and return a unibyte string",
         NULL);
    bind(env,
         Fcall_re_code_len, "readelf--code-len", 1, 1,
         "Return the length of opaque CODE object",
         NULL);
    bind(env,
         Fcall_re_code_substr, "readelf--code-substr", 3, 3,
         "From opaque CODE object, return the bytes at START and max length SIZE",
         NULL);
    bind(env,
         Fcall_re_foreach_insn, "readelf--foreach-insn", 2, 2,
         "Call FUNCTION on each instruction in INSN-BLOCK",
         NULL);

    emacs_value provide_args[1];
    
    provide_args[0] = _CS_INTERN("capstone-core");
    _CS_FUNCALL("provide", provide_args); 
    return 0;
}
