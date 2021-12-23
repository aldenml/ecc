import json
import sys


class ParmVarDecl:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]


class FunctionDecl:
    def __init__(self, ast):
        self.ast = ast
        self.name = ast["name"]
        self.mangledName = ast["mangledName"]

    def params(self):
        return list(map(lambda e: ParmVarDecl(e), filter(lambda e: e["kind"] == "ParmVarDecl", self.ast["inner"])))


class TranslationUnitDecl:
    def __init__(self, ast):
        self.ast = ast

    def functions(self):
        return list(map(lambda e: FunctionDecl(e), filter(lambda e: e["kind"] == "FunctionDecl", self.ast["inner"])))


def read_ast_json(filename):
    f = open(filename, "r")
    ast = json.loads(f.read())
    f.close()
    return ast


translationUnit = TranslationUnitDecl(read_ast_json(sys.argv[1]))
functions = translationUnit.functions()
print(functions[0].name)
print(functions[0].params()[0].name)
#
# functionDecl = functions[0]
# name = functionDecl.name
# mangledName = functionDecl["mangledName"]
#
# params = list(filter(lambda e: e["kind"] == "ParmVarDecl", functionDecl["inner"]))
# print("name: " + name)
# print("mangledName: " + mangledName)
