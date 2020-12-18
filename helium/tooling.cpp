#include <iostream>
#include <vector>

#include <clang/Tooling/Tooling.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/AST/RecursiveASTVisitor.h>

#include <unistd.h>

using std::string;
using namespace clang;
using namespace clang::tooling;
using std::unique_ptr;
using std::vector;

bool is_in_main(Decl *decl) {
  ASTContext &ctx = decl->getASTContext();
  SourceManager &mgr = ctx.getSourceManager();
  SourceLocation loc = decl->getLocation();
  return mgr.isInMainFile(loc);
}

// class MyASTConsumer : public ASTConsumer {
// public:
  
// private:
// };

// class MyAction : public ASTFrontendAction {
// public:
//   unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) {
//     return new MyASTConsumer();
//   }
// private:
// };


class MyVisitor : public RecursiveASTVisitor<MyVisitor> {
public:
  bool VisitDecl(Decl *decl) {
    if (!is_in_main(decl)) return false;
    return true;
  }
  bool VisitTranslationUnitDecl(TranslationUnitDecl *tu) {
    std::cout << "Translation Unit" << "\n";
    return true;
  }
  bool VisitFunctionDecl(FunctionDecl *func) {
    std::cout << "Function Decl" << "\n";
    return true;
  }
  bool VisitIfStmt(IfStmt *ifstmt) {
    std::cout << "IfStmt" << "\n";
    return true;
  }
};

void process_bench(string bench_dir, string file) {
  std::cout << "Reading compilation database .." << "\n";
  string err_msg;
  unique_ptr<CompilationDatabase> db = CompilationDatabase::loadFromDirectory(bench_dir, err_msg);
  std::cout << "Database:" << "\n";
  vector<CompileCommand> cmds = db->getCompileCommands(file);
  for (auto cmd : cmds) {
    std::cout << cmd.Directory << "\n";
    std::cout << cmd.Filename << "\n";
    // for (string s : cmd.CommandLine) {
    //   std::cout << s << "\n";
    // }
    std::cout << cmd.Output << "\n";
  }

  // clang::tooling::CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
  // clang::tooling::ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());


  chdir(bench_dir.c_str());
  ArrayRef<string> srcs = {"kernel/acct.c"};
  ClangTool tool (*db, srcs);

  vector<unique_ptr<ASTUnit> > units;
  tool.buildASTs(units);
  std::cout << units.size() << "\n";

  for (std::unique_ptr<clang::ASTUnit> &unit : units) {
    clang::ASTContext &ast = unit->getASTContext();
    clang::TranslationUnitDecl *tu = ast.getTranslationUnitDecl();
    // traversing the AST and dump a AST format
    MyVisitor visitor;
    visitor.TraverseDecl(tu);
  }
}

int main() {
  string bench_dir = "/home/hebi/Downloads/linux-4.14.9";
  string file = "/home/hebi/Downloads/linux-4.14.9/kernel/acct.c";

  process_bench(bench_dir, file);
  
  return 0;
}
