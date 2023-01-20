#
# Copyright (c) 2021-2023, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

import json
import re
import subprocess
import textwrap


class ParamComment:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["param"]
        self.direction = ast["direction"]

    def comment_text(self):
        paragraphs = list(map(
            lambda e: "\n".join(map(lambda t: t["text"].strip(), e["inner"])).strip(),
            filter(lambda e: e["kind"] == "ParagraphComment", self.ast["inner"])
        ))
        return "\n".join(filter(None, paragraphs))


class FullComment:
    def __init__(self, ast):
        self.ast = ast

    def comment_text(self):
        paragraphs = list(map(
            lambda e: "\n".join(map(lambda t: t["text"].strip(), e["inner"])),
            filter(lambda e: e["kind"] == "ParagraphComment", self.ast["inner"])
        ))
        return "\n\n".join(filter(None, paragraphs))

    def comment_params(self):
        return list(map(
            lambda e: ParamComment(e),
            filter(lambda e: e["kind"] == "ParamCommandComment", self.ast["inner"])
        ))

    def comment_return(self):
        return_comments = list(filter(
            lambda e: e["kind"] == "BlockCommandComment" and e["name"] == "return",
            self.ast["inner"]
        ))
        if len(return_comments) > 0:
            return return_comments[0]["inner"][0]["inner"][0]["text"].strip()
        else:
            return None


class ParmVarDecl:
    def __init__(self, ast, comment):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]
        self.type = ast["type"]["qualType"]
        self.comment = comment
        if comment is None:
            raise RuntimeError("Param without comment: " + self.name)

    def is_array(self):
        if self.type == "const byte_t *":
            return True
        elif self.type == "byte_t *":
            return True
        else:
            return False

    def impl_name(self):
        if self.is_array():
            return "ptr_" + self.name
        else:
            return self.name

    def direction(self):
        return self.comment.direction

    def is_out(self):
        return self.direction() == "out"

    def is_inout(self):
        return self.direction() == "in,out"

    def size(self):
        text = self.comment.comment_text()
        match = re.search(r"\bsize:([A-Za-z0-9_+\-*/()]+)", text)
        if match is None:
            print("No size specified: " + text)
        return match.group(1)

    def type_js(self):
        if self.type == "int":
            return "number"
        elif self.is_array():
            return "Uint8Array"
        else:
            return self.type


class DefineDecl:
    def __init__(self, match):
        self.comment = match[0].replace(" * ", "").strip()
        self.name = match[1]
        self.value = match[2]

    def build_js(self):
        out = ""
        out += "const " + self.name + " = " + self.value + ";\n"
        out += "/**\n"
        out += " * "
        out += " * ".join(self.comment.splitlines(True)) + "\n"
        out += " *\n"
        out += " * @type {number}\n"
        out += " */\n"
        out += "Module." + self.name + " = " + self.name + ";\n"
        return out

    def build_jni_java(self):
        out = ""
        out += "    /**\n"
        out += "     * "
        out += "     * ".join(self.comment.splitlines(True)) + "\n"
        out += "     *\n"
        out += "     */\n"
        out += "    public static final int " + self.name + " = " + self.value + ";\n"
        return out

    def build_python(self):
        out = ""
        out += self.name + " = " + self.value + "\n"
        out += "\"\"\"\n"
        out += "".join(self.comment.splitlines(True)) + "\n"
        out += "\"\"\"\n"
        return out


class VarDecl:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]
        self.type = ast["type"]["qualType"]

    def value(self):
        return self.ast["inner"][0]["value"]

    def comment(self):
        return list(map(
            lambda e: FullComment(e),
            filter(lambda e: e["kind"] == "FullComment", self.ast["inner"])
        ))[0]

    def type_js(self):
        if self.type == "const int":
            return "number"
        elif self.type == "int":
            return "number"
        else:
            return self.type

    def build_js(self):
        comment = self.comment()
        out = ""
        out += "const " + self.name + " = " + self.value() + ";\n"
        out += "/**\n"
        out += " * "
        out += " * ".join(comment.comment_text().splitlines(True)) + "\n"
        out += " *\n"
        out += " * @type {" + self.type_js() + "}\n"
        out += " */\n"
        out += "Module." + self.name + " = " + self.name + ";\n"
        return out


class FunctionDecl:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]

    def params(self):
        comments = self.comment().comment_params()
        return list(map(
            lambda e: ParmVarDecl(e, next(filter(lambda c: c.name == e["name"], comments))),
            filter(lambda e: e["kind"] == "ParmVarDecl", self.ast["inner"])
        ))

    def comment(self):
        return list(map(
            lambda e: FullComment(e),
            filter(lambda e: e["kind"] == "FullComment", self.ast["inner"])
        ))[0]

    def return_type(self):
        text = self.ast["type"]["qualType"]
        match = re.search(r"^(\w+)\b", text)
        return match.group(1)

    def build_js(self):
        comment = self.comment()
        out = ""
        out += "/**\n"
        out += " * "
        out += " * ".join(comment.comment_text().splitlines(True)) + "\n"
        out += " *\n"
        for param in self.params():
            out += " * @param {" + param.type_js() + "} " + param.name
            if param.is_out():
                out += " (output)"
            if param.is_inout():
                out += " (input, output)"
            out += " "
            out += " * ".join(param.comment.comment_text().splitlines(True)) + "\n"
        if comment.comment_return() is not None:
            out += " * @return {number} " + comment.comment_return() + "\n"
        out += " */\n"
        out += "Module." + self.name + " = (\n"
        for param in self.params():
            out += "    " + param.name + ",\n"
        out += ") => {\n"
        # alloc
        for param in self.params():
            if param.is_array():
                out += "    const " + param.impl_name() + " = mput(" + param.name + ", " + param.size() + ");\n"
        # invoke
        if self.return_type() != "void":
            out += "    const fun_ret = " + self.mangledName + "(\n"
        else:
            out += "    " + self.mangledName + "(\n"
        for param in self.params():
            out += "        " + param.impl_name() + ",\n"
        out += "    );\n"
        # get
        for param in self.params():
            if param.is_array() and (param.is_out() or param.is_inout()):
                out += "    mget(" + param.name + ", " + param.impl_name() + ", " + param.size() + ");\n"
        # free
        for param in self.params():
            if param.is_array():
                out += "    mfree(" + param.impl_name() + ", " + param.size() + ");\n"
        # return
        if self.return_type() != "void":
            out += "    return fun_ret;\n"
        out += "}\n"
        return out

    def build_jni_c(self):
        out = ""
        out += "JNIEXPORT "
        if self.return_type() != "void":
            out += "int"
        else:
            out += "void"
        out += " JNICALL Java_org_ssohub_crypto_ecc_libecc_" + self.name.replace("_", "_1") + "(\n"
        out += "    JNIEnv *env, jclass cls,\n"
        out += ",\n".join(map(
            lambda p: "    jbyteArray " + p.name if (p.is_array()) else "    jint " + p.name,
            self.params()
        ))
        out += "\n) {\n"
        # alloc
        for param in self.params():
            if param.is_array():
                out += "    byte_t *" + param.impl_name() + " = mput(env, " + param.name + ", " + param.size() + ");\n"
        # invoke
        if self.return_type() != "void":
            out += "    const int fun_ret = " + self.name + "(\n"
        else:
            out += "    " + self.name + "(\n"
        out += ",\n".join(map(lambda p: "        " + p.impl_name(), self.params()))
        out += "\n"
        out += "    );\n"
        # get
        for param in self.params():
            if param.is_array() and (param.is_out() or param.is_inout()):
                out += "    mget(env, " + param.name + ", " + param.impl_name() + ", " + param.size() + ");\n"
        # free
        for param in self.params():
            if param.is_array():
                out += "    mfree(" + param.impl_name() + ", " + param.size() + ");\n"
        # return
        if self.return_type() != "void":
            out += "    return fun_ret;\n"
        out += "}\n"
        return out

    def build_jni_java(self):
        comment = self.comment()
        out = ""
        out += "    /**\n"
        out += "     * "
        out += "     * ".join(comment.comment_text().splitlines(True)) + "\n"
        out += "     *\n"
        for param in self.params():
            out += "     * @param " + param.name
            if param.is_out():
                out += " (output)"
            if param.is_inout():
                out += " (input, output)"
            out += " "
            out += "     * ".join(param.comment.comment_text().splitlines(True)) + "\n"
        if comment.comment_return() is not None:
            out += "     * @return " + comment.comment_return() + "\n"
        out += "     */\n"
        out += "    public static native "
        if self.return_type() != "void":
            out += "int"
        else:
            out += "void"
        out += " " + self.name + "(\n"
        out += ",\n".join(map(
            lambda p: "        byte[] " + p.name if (p.is_array()) else "        int " + p.name,
            self.params()
        ))
        out += "\n    );\n"
        return out

    def build_cffi_python(self):
        out = ""
        out += "    "
        if self.return_type() != "void":
            out += "int"
        else:
            out += "void"
        out += " " + self.name + "(\n"
        out += ",\n".join(map(
            lambda p: "        unsigned char *" + p.name if (p.is_array()) else "        int " + p.name,
            self.params()
        ))
        out += "\n    );\n"
        return out

    def build_python(self):
        comment = self.comment()
        out = ""
        out += "def " + self.name + "(\n"
        out += ",\n".join(map(
            lambda p: "    " + p.name + ((": bytearray" if (p.is_out() or p.is_inout()) else ": bytes") if (p.is_array()) else ": int"),
            self.params()
        ))
        out += "\n) -> "
        if self.return_type() != "void":
            out += "int"
        else:
            out += "None"
        out += ":\n"
        out += "    \"\"\"\n"
        out += "    "
        out += "    ".join(comment.comment_text().splitlines(True)) + "\n"
        out += "    \n"
        for param in self.params():
            out += "    " + param.name + " --"
            if param.is_out():
                out += " (output)"
            if param.is_inout():
                out += " (input, output)"
            out += " "
            out += "    ".join(param.comment.comment_text().splitlines(True)) + "\n"
        if comment.comment_return() is not None:
            out += "    return " + comment.comment_return() + "\n"
        out += "    \"\"\"\n"
        # alloc
        for param in self.params():
            if param.is_array():
                out += "    " + param.impl_name() + " = ffi.from_buffer(" + param.name + ")\n"
        # invoke
        if self.return_type() != "void":
            out += "    fun_ret = lib." + self.name + "(\n"
        else:
            out += "    lib." + self.name + "(\n"
        out += ",\n".join(map(lambda p: "        " + p.impl_name(), self.params()))
        out += "\n"
        out += "    )\n"
        # return
        if self.return_type() != "void":
            out += "    return fun_ret\n"
        else:
            out += "    return None\n"
        out += "\n"
        return out


class TranslationUnitDecl:
    def __init__(self, ast, text):
        self.ast = ast
        self.text = text

    def defines(self):
        matches = re.findall(r"// const\n/\*\*(.*?)\*/\n#define ([A-Za-z0-9_]+?) ([0-9]+?)\n\n", self.text,
                             flags=re.DOTALL)
        return list(map(
            lambda e: DefineDecl(e),
            matches
        ))

    def constants(self):
        return list(map(
            lambda e: VarDecl(e),
            filter(lambda e: e["kind"] == "VarDecl", self.ast["inner"])
        ))

    def functions(self, ignore):
        return list(map(
            lambda e: FunctionDecl(e),
            filter(lambda e: e["kind"] == "FunctionDecl" and e["name"] not in ignore, self.ast["inner"])
        ))

    def build_js(self, ignore):
        defines = self.defines()
        functions = self.functions(ignore)
        out = ""
        out += "\n".join(map(lambda c: c.build_js(), defines))
        out += "\n"
        out += "\n".join(map(lambda f: f.build_js(), functions))
        return out

    def build_jni_c(self, ignore):
        functions = self.functions(ignore)
        out = ""
        out += "\n".join(map(lambda f: f.build_jni_c(), functions))
        return out

    def build_jni_java(self, ignore):
        defines = self.defines()
        functions = self.functions(ignore)
        out = ""
        out += "\n".join(map(lambda c: c.build_jni_java(), defines))
        out += "\n"
        out += "\n".join(map(lambda f: f.build_jni_java(), functions))
        return out

    def build_cffi_python(self, ignore):
        functions = self.functions(ignore)
        out = ""
        out += "\n".join(map(lambda f: f.build_cffi_python(), functions))
        return out

    def build_python(self, ignore):
        defines = self.defines()
        functions = self.functions(ignore)
        out = ""
        out += "\n".join(map(lambda c: c.build_python(), defines))
        out += "\n"
        out += "\n".join(map(lambda f: f.build_python(), functions))
        return out


def gen_ast(header):
    # clang -Xclang -ast-dump=json -fsyntax-only src/{header}.h
    filename = "src/" + header + ".h"
    output = subprocess.run(
        ["clang", "-Xclang", "-ast-dump=json", "-fsyntax-only", filename],
        capture_output=True, text=True
    ).stdout
    return json.loads(output)


def read_header(header):
    filename = "src/" + header + ".h"
    with open(filename, "r") as f:
        return f.read()


ecc_headers = ["util", "hash", "mac", "kdf", "ed25519", "ristretto255", "bls12_381",
               "h2c", "voprf", "opaque", "sign", "frost", "pre"]
ecc_ignore = ["ecc_memzero", "ecc_bin2hex", "ecc_hex2bin", "ecc_malloc", "ecc_free", "ecc_log"]


def gen_js(headers, ignore):
    out = ""
    out += "/**\n"
    out += " * @param {Uint8Array} src\n"
    out += " * @param {number} srcPos\n"
    out += " * @param {Uint8Array} dest\n"
    out += " * @param {number} destPos\n"
    out += " * @param {number} length\n"
    out += " */\n"
    out += "function arraycopy(src, srcPos, dest, destPos, length) {\n"
    out += "    dest.set(src.subarray(srcPos, srcPos + length), destPos);\n"
    out += "}\n"
    out += "\n"
    out += "/**\n"
    out += " * @param {Uint8Array} src\n"
    out += " * @param {number} size\n"
    out += " * @return {number}\n"
    out += " */\n"
    out += "function mput(src, size) {\n"
    out += "    if (!src) return 0;\n"
    out += "    const pos = _ecc_malloc(size);\n"
    out += "    arraycopy(src, 0, HEAPU8, pos, size);\n"
    out += "    return pos;\n"
    out += "}\n"
    out += "\n"
    out += "/**\n"
    out += " * @param {Uint8Array} dest\n"
    out += " * @param {number} pos\n"
    out += " * @param {number} size\n"
    out += " */\n"
    out += "function mget(dest, pos, size) {\n"
    out += "    arraycopy(HEAPU8, pos, dest, 0, size);\n"
    out += "}\n"
    out += "\n"
    out += "/**\n"
    out += " * @param {number} ptr\n"
    out += " * @param {number} size\n"
    out += " */\n"
    out += "function mfree(ptr, size) {\n"
    out += "    _ecc_free(ptr, size);\n"
    out += "}\n"
    out += "\n"
    out += "\n".join(map(
        lambda h: "// " + h + "\n\n" + TranslationUnitDecl(gen_ast(h), read_header(h)).build_js(ignore),
        headers
    ))
    return out


def gen_jni_c(headers, ignore):
    out = ""
    out += "/*\n"
    out += " * Copyright (c) 2021-2023, Alden Torres\n"
    out += " *\n"
    out += " * Licensed under the terms of the MIT license.\n"
    out += " * Copy of the license at https://opensource.org/licenses/MIT\n"
    out += " */\n"
    out += "\n"
    out += "#include \"jni.h\"\n"
    out += "#include <ecc.h>\n"
    out += "\n"
    out += "byte_t *mput(JNIEnv *env, jbyteArray src, int size) {\n"
    out += "    if (src != NULL) {\n"
    out += "        byte_t *ptr = ecc_malloc(size);\n"
    out += "        (*env)->GetByteArrayRegion(env, src, 0, size, (jbyte *) ptr);\n"
    out += "        return ptr;\n"
    out += "    }\n"
    out += "    return NULL;\n"
    out += "}\n"
    out += "\n"
    out += "void mget(JNIEnv *env, jbyteArray dest, byte_t *ptr, int size) {\n"
    out += "    (*env)->SetByteArrayRegion(env, dest, 0, size, (jbyte *) ptr);\n"
    out += "}\n"
    out += "\n"
    out += "void mfree(byte_t *ptr, int size) {\n"
    out += "    ecc_free(ptr, size);\n"
    out += "}\n"
    out += "\n"
    out += "#ifdef __cplusplus\n"
    out += "extern \"C\" {\n"
    out += "#endif\n"
    out += "\n"
    out += "\n".join(map(
        lambda h: "// " + h + "\n\n" + TranslationUnitDecl(gen_ast(h), read_header(h)).build_jni_c(ignore),
        headers
    ))
    out += "\n"
    out += "#ifdef __cplusplus\n"
    out += "}\n"
    out += "#endif\n"
    out += "\n"
    return out


def gen_jni_java(headers, ignore):
    out = ""
    out += "/*\n"
    out += " * Copyright (c) 2021-2023, Alden Torres\n"
    out += " *\n"
    out += " * Licensed under the terms of the MIT license.\n"
    out += " * Copy of the license at https://opensource.org/licenses/MIT\n"
    out += " */\n"
    out += "\n"
    out += "package org.ssohub.crypto.ecc;\n"
    out += "\n"
    out += "/**\n"
    out += " * JNI java interface for libecc-jvm.\n"
    out += " *\n"
    out += " * @author aldenml\n"
    out += " */\n"
    out += "public final class libecc {\n"
    out += "\n"
    out += "    static {\n"
    out += "        try {\n"
    out += "            String path = System.getProperty(\"libecc.jni.path\", \"\");\n"
    out += "            if (\"\".equals(path)) {\n"
    out += "                String libname = \"ecc-jvm\";\n"
    out += "                String os = System.getProperty(\"os.name\");\n"
    out += "                if (os != null && os.toLowerCase(java.util.Locale.US).contains(\"windows\"))\n"
    out += "                    libname = \"lib\" + libname;\n"
    out += "                System.loadLibrary(libname);\n"
    out += "            } else {\n"
    out += "                System.load(path);\n"
    out += "            }\n"
    out += "        } catch (LinkageError e) {\n"
    out += "            throw new LinkageError(\n"
    out += "                \"Look for your architecture binary instructions at: https://github.com/aldenml/ecc\",\n"
    out += "                e);\n"
    out += "        }\n"
    out += "    }\n"
    out += "\n"
    out += "    private libecc() {\n"
    out += "    }\n"
    out += "\n"
    out += "\n".join(map(
        lambda h: "    // " + h + "\n\n" + TranslationUnitDecl(gen_ast(h), read_header(h)).build_jni_java(ignore),
        headers
    ))
    out += "\n"
    out += "}\n"
    return out


def gen_cffi_python(headers, ignore):
    out = ""
    out += "#\n"
    out += "# Copyright (c) 2021-2023, Alden Torres\n"
    out += "#\n"
    out += "# Licensed under the terms of the MIT license.\n"
    out += "# Copy of the license at https://opensource.org/licenses/MIT\n"
    out += "#\n"
    out += "\n"
    out += "from cffi import FFI\n"
    out += "\n"
    out += "ffibuilder = FFI()\n"
    out += "\n"
    out += "ffibuilder.cdef(\n"
    out += "    \"\"\"\n"
    out += "\n".join(map(
        lambda h: "    // " + h + "\n\n" + TranslationUnitDecl(gen_ast(h), read_header(h)).build_cffi_python(ignore),
        headers
    ))
    out += "\n    \"\"\"\n"
    out += ")\n"
    out += textwrap.dedent(
        """
        ffibuilder.set_source(
            module_name="_libecc_cffi",
            source=
            \"\"\"
            #include "../../../../src/ecc.h"
            \"\"\",
            include_dirs=["../../../src"],
            library_dirs=["../../../../build", "../../../../build/libsodium/lib", "../../../../deps/blst"],
            libraries=["ecc_static", "sodium", "blst"]
        )
    
        if __name__ == "__main__":
            ffibuilder.compile(tmpdir="src/libecc", verbose=True)
        """)
    return out


def gen_python(headers, ignore):
    out = ""
    out += "#\n"
    out += "# Copyright (c) 2021-2023, Alden Torres\n"
    out += "#\n"
    out += "# Licensed under the terms of the MIT license.\n"
    out += "# Copy of the license at https://opensource.org/licenses/MIT\n"
    out += "#\n"
    out += "\n"
    out += "from ._libecc_cffi import ffi, lib\n\n"
    out += "\n".join(map(
        lambda h: "# " + h + "\n\n" + TranslationUnitDecl(gen_ast(h), read_header(h)).build_python(ignore),
        headers
    ))
    return out


def gen_code(headers, ignore):
    with open("bindings/js/libecc-post.js", "w") as f:
        f.write(gen_js(headers, ignore))
    with open("bindings/jvm/libecc.c", "w") as f:
        f.write(gen_jni_c(headers, ignore))
    with open("bindings/jvm/src/main/java/org/ssohub/crypto/ecc/libecc.java", "w") as f:
        f.write(gen_jni_java(headers, ignore))
    # with open("bindings/python/cffi_build.py", "w") as f:
    #     f.write(gen_cffi_python(headers, ignore))
    # with open("bindings/python/src/libecc/libecc.py", "w") as f:
    #     f.write(gen_python(headers, ignore))


gen_code(ecc_headers, ecc_ignore)
