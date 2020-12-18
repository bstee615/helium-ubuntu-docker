#ifndef SEXP_H
#define SEXP_H

#include <clang/AST/AST.h>


std::string escape_string(std::string input);

class Sexp {
public:
  Sexp() {}
  virtual ~Sexp() {}
  virtual void dump(std::ostream &os) = 0;
};

class ListSexp : public Sexp {
public:
  // sexp is either a string
  ListSexp() {}
  ~ListSexp() {
    for (Sexp *v : values) {
      if (v) delete v;
    }
  }
  // or a list of key, Sexp pairs
  void add(Sexp *value) {
    // FIXME
    // if (value == nullptr) return;
    values.push_back(value);
  }
  virtual void dump(std::ostream &os) {
    os << "\n(";
    for (Sexp *v : values) {
      if (v) v->dump(os);
      else os << "\n#f"; // add \n to maintain indentation
      os << " ";
    }
    os << ")";
  }
protected:
  std::vector<Sexp*> values;
};

class ConsSexp : public Sexp {
public:
  ConsSexp(Sexp *car, Sexp *cdr) {
    this->car = car;
    this->cdr = cdr;
  }
  ~ConsSexp() {
    if (car) delete car;
    if (cdr) delete cdr;
  }
  virtual void dump(std::ostream &os) {
    os << "(";
    if (car) car->dump(os);
    else os << "#f";
    os << " . ";
    if (cdr) cdr->dump(os);
    else os << "#f";
    os << ")";
  }
protected:
  Sexp *car = nullptr;
  Sexp *cdr = nullptr;
};

struct Loc {
  int bl=0;
  int bc=0;
  int el=0;
  int ec=0;
  Loc(int bl, int bc, int el, int ec) {
    this->bl = bl;
    this->bc = bc;
    this->el = el;
    this->ec = ec;
  }
  friend std::ostream& operator << (std::ostream& os, const Loc& loc) {
    return os << "(" << loc.bl << " " << loc.bc << " " << loc.el << " " << loc.ec << ")";
  }
};


class StructSexp : public ListSexp {
public:
  StructSexp(std::string key) {
    this->key = key;
  }
  virtual void dump(std::ostream &os) {
    // the first field is reserved for downstream app, like color in
    // Helium
    os << "\n#s(" << key << " (none " << loc;
    // extra attr
    if (!attr.empty()) {
      os << " " << attr;
    }
    os << ") ";
    for (Sexp *v : values) {
      if (v) v->dump(os);
      else os << "\n#f";
      os << " ";
    }
    os << ")";
  }
  void SetLoc(Loc loc) {
    this->loc = loc;
  }
  void SetExtraAttr(std::string attr) {
    this->attr = attr;
  }
private:
  std::string key;
  Loc loc = {0,0,0,0};
  std::string attr;
};

class StringSexp : public Sexp {
public:
  StringSexp(std::string value) {
    this->value = value;
  }
  virtual ~StringSexp() {}
  virtual void dump(std::ostream &os) {
    os << "\"" << escape_string(value) << "\"";
  }
private:
  std::string value;
};
class SymbolSexp : public Sexp {
public:
  SymbolSexp(std::string symbol) {
    this->symbol = symbol;
  }
  virtual ~SymbolSexp() override {}
  virtual void dump(std::ostream &os) override {
    // if (!symbol.empty() && symbol[0] == ':') {
    //   os << "\n";
    // }
    os << symbol;
  }
private:
  std::string symbol;
};


// std::string gen_he(clang::TranslationUnitDecl *tu, clang::SourceManager &mgr);
void process_tu(clang::TranslationUnitDecl *tu, clang::SourceManager &mgr);


// Sexp* parse_Expr(clang::Expr *expr, clang::SourceManager &mgr);
Sexp* parse_Expr(clang::Expr *expr, clang::SourceManager &mgr);

Sexp* parse_Decl(clang::Decl *decl, clang::SourceManager &mgr);
Sexp* parse_TranslationUnitDecl(clang::TranslationUnitDecl *tu, clang::SourceManager &mgr);
Sexp* parse_FunctionDecl(clang::FunctionDecl *func, clang::SourceManager &mgr);
Sexp* parse_LabelDecl(clang::LabelDecl *label, clang::SourceManager &mgr);
Sexp* parse_EnumConstantDecl(clang::EnumConstantDecl *decl, clang::SourceManager &mgr);
Sexp* parse_EnumDecl(clang::EnumDecl *decl, clang::SourceManager &mgr);
Sexp* parse_FieldDecl(clang::FieldDecl *field, clang::SourceManager &mgr);
Sexp* parse_RecordDecl(clang::RecordDecl *record, clang::SourceManager &mgr);
Sexp* parse_TypedefNameDecl(clang::TypedefNameDecl *decl, clang::SourceManager &mgr);
Sexp* parse_VarDecl(clang::VarDecl *var, clang::SourceManager &mgr);


Sexp* parse_Stmt(clang::Stmt *stmt, clang::SourceManager &mgr);
Sexp* parse_DeclStmt(clang::DeclStmt *decl_stmt, clang::SourceManager &mgr);
Sexp* parse_CompoundStmt(clang::CompoundStmt *comp, clang::SourceManager &mgr);
Sexp* parse_IfStmt(clang::IfStmt *if_stmt, clang::SourceManager &mgr);
Sexp* parse_CaseStmt(clang::CaseStmt *stmt, clang::SourceManager &mgr);
Sexp* parse_DefaultStmt(clang::DefaultStmt *stmt, clang::SourceManager &mgr);
Sexp* parse_SwitchStmt(clang::SwitchStmt *switch_stmt, clang::SourceManager &mgr);
Sexp* parse_ForStmt(clang::ForStmt *for_stmt, clang::SourceManager &mgr);
Sexp* parse_DoStmt(clang::DoStmt *do_stmt, clang::SourceManager &mgr);
Sexp* parse_WhileStmt(clang::WhileStmt *while_stmt, clang::SourceManager &mgr);
Sexp* parse_BreakStmt(clang::BreakStmt *break_stmt, clang::SourceManager &mgr);
Sexp* parse_ContinueStmt(clang::ContinueStmt *cont, clang::SourceManager &mgr);
Sexp* parse_ReturnStmt(clang::ReturnStmt *ret_stmt, clang::SourceManager &mgr);
Sexp* parse_ExprStmt(clang::Expr *expr, clang::SourceManager &mgr);
Sexp* parse_NullStmt(clang::NullStmt *null_stmt, clang::SourceManager &mgr);

// Sexp* create_loc(clang::SourceManager &mgr, clang::SourceRange range, clang::SourceManager &mgr);
// Sexp* create_token(clang::SourceManager &mgr, std::string src, clang::SourceRange range, clang::SourceManager &mgr);
// Sexp* create_next_token(clang::SourceManager &mgr, clang::SourceLocation loc, unsigned offset, clang::SourceManager &mgr);

Sexp *parse_GotoStmt(clang::GotoStmt *goto_stmt, clang::SourceManager &mgr);
Sexp *parse_LabelStmt(clang::LabelStmt *label_stmt, clang::SourceManager &mgr);

Sexp *parse_QualType(clang::QualType t, clang::SourceManager &mgr);

// std::string gen_loc_name(clang::SourceLocation loc, clang::SourceManager &mgr);
// std::string gen_anonymous_tag_name(clang::TagDecl *tag, clang::SourceManager &mgr);
// std::string rewrite_anony(std::string str);

#endif /* SEXP_H */
