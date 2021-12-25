import json
import re
import subprocess


class ParamComment:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["param"]
        self.direction = ast["direction"]

    def comment_text(self):
        return self.ast["inner"][0]["inner"][0]["text"].strip()


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


class ParmVarDecl:
    def __init__(self, ast, comment):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]
        self.type = ast["type"]["qualType"]
        self.comment = comment

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

    def size(self):
        text = self.comment.comment_text()
        match = re.search(r"\bsize:([A-Za-z0-9_+\-*/]+)", text)
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
            out += " " + param.comment.comment_text() + "\n"
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
            out += "    const r = " + self.mangledName + "(\n"
        else:
            out += "    " + self.mangledName + "(\n"
        for param in self.params():
            out += "        " + param.impl_name() + ",\n"
        out += "    );\n"
        # get
        for param in self.params():
            if param.is_array() and param.is_out():
                out += "    mget(" + param.name + ", " + param.impl_name() + ", " + param.size() + ");\n"
        # free
        for param in self.params():
            if param.is_array():
                out += "    mfree(" + param.impl_name() + ", " + param.size() + ");\n"
        # return
        if self.return_type() != "void":
            out += "    return r;\n"
        out += "}\n"
        return out


class TranslationUnitDecl:
    def __init__(self, ast, text):
        self.ast = ast
        self.text = text

    def defines(self):
        matches = re.findall(r"// const\n/\*\*(.*?)\*/\n#define ([A-Za-z0-9_]+?) ([0-9]+?)\n\n", self.text, flags=re.DOTALL)
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
               "h2c", "oprf", "opaque", "sign", "pre"]
ecc_ignore = ["ecc_memzero", "ecc_bin2hex", "ecc_hex2bin", "ecc_malloc", "ecc_free"]


def gen_js(headers, ignore):
    out = ""
    out += "\n".join(map(
        lambda h: TranslationUnitDecl(gen_ast(h), read_header(h)).build_js(ignore),
        headers
    ))
    return out


print(gen_js(["bls12_381"], ecc_ignore))
