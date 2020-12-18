#include <iostream>
#include <fstream>
#include "plugin.h"
#include "sexp.h"

using namespace std;
using namespace clang;

void pretty_rewrite(string filename) {
  // read
  ifstream is;
  is.open(filename);
  string content;
  string line;
  while (getline(is, line)) {
    content += line + "\n";
  }
  is.close();

  // pretty print
  
  // write back
  ofstream os;
  os.open(filename);
}


class MyASTConsumer : public ASTConsumer {
public:
  MyASTConsumer(CompilerInstance &CI) {
  }
  void HandleTranslationUnit (ASTContext &ctx) override {
    // this is done after translation unit is generated
    // 1. get the translation unit
    // 2. dump everything to a file, with the same name,
    //    in the same directory, with extension .scm
    llvm::errs() << "==== In Helium Plugin" << "\n";
    TranslationUnitDecl *tu = ctx.getTranslationUnitDecl();
    SourceManager &mgr = ctx.getSourceManager();
    
    process_tu(tu, mgr);
    

    // pretty_rewrite(output_file);
    llvm::errs() << "==== Helium plugin finished" << "\n";
  }
};

class MyPlugin : public PluginASTAction {
protected:
  unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, llvm::StringRef) override {
    return std::make_unique<MyASTConsumer>(CI);
  }
  bool ParseArgs(const CompilerInstance &CI, const std::vector<std::string> &args) override {
    for (unsigned i=0;i<args.size();i++) {
      llvm::errs() << "Helium Plugin: arg = " << args[i] << "\n";
    }
    return true;
  }
  // having this, this plugin will be run automatically
  ActionType getActionType() override {
    return AddAfterMainAction;
  }
};


// call the plugin by
//      clang -IXXX ... -Xclang -load -Xclang /path/to/libhelium.so -Xclang -add-plugin -Xclang helium
// Note that every command is prefixed with -Xclang
// Actually the arguments are
//      clang -load /path/to/helium.so -add-plugin helium
// Adding getActionType, the plugin is run automatically when loaded
//      clang -load /path/to/helium.so xxx.c
static FrontendPluginRegistry::Add<MyPlugin> X("helium", "generate AST dump S-exp during compilation");
