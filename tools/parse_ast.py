import json
import sys
import re


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
        match = re.search(r"\bsize:(\w+)\b", text)
        return match.group(1)

    def type_js(self):
        if self.type == "int":
            return "number"
        elif self.is_array():
            return "Uint8Array"
        else:
            return self.type


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
        if self.type == " const int":
            return "number"
        elif self.type == " int":
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
    def __init__(self, ast):
        self.ast = ast

    def constants(self):
        return list(map(
            lambda e: VarDecl(e),
            filter(lambda e: e["kind"] == "VarDecl", self.ast["inner"])
        ))

    def functions(self):
        return list(map(
            lambda e: FunctionDecl(e),
            filter(lambda e: e["kind"] == "FunctionDecl", self.ast["inner"])
        ))


def read_ast_json(filename):
    f = open(filename, "r")
    ast = json.loads(f.read())
    f.close()
    return ast


translationUnit = TranslationUnitDecl(read_ast_json(sys.argv[1]))
constants = translationUnit.constants()
functions = translationUnit.functions()
print(functions[0].name)
print(functions[0].return_type())
print(functions[0].params()[0].name)
print(functions[0].comment().comment_text())
print(functions[0].comment().comment_params()[0].comment_text())
print(functions[0].params()[0].size())
print(functions[0].build_js())
print(constants[0].build_js())
#
# functionDecl = functions[0]
# name = functionDecl.name
# mangledName = functionDecl["mangledName"]
#
# params = list(filter(lambda e: e["kind"] == "ParmVarDecl", functionDecl["inner"]))
# print("name: " + name)
# print("mangledName: " + mangledName)
