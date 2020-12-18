#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <regex>
#include "sexp.h"
#include <clang/Lex/Lexer.h>
#include <clang/Rewrite/Core/Rewriter.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Basic/FileManager.h>

using namespace std;
using namespace clang;

// #define HELIUM_PARSE_TREE

string decl_to_str(clang::Decl *decl) {
  // ostringstream os;
  string ret;
  llvm::raw_string_ostream os(ret);
  PrintingPolicy policy = PrintingPolicy(LangOptions());
  // policy.IncludeTagDefinition = 1;
  decl->print(os, policy);
  os.flush();
  // FIXME is this the same as ret?
  return os.str();
}

/**
 * Works for both stmt and expr
 */
string stmt_to_str(clang::Stmt *stmt) {
  string ret;
  llvm::raw_string_ostream os(ret);
  stmt->printPretty(os, nullptr, PrintingPolicy(LangOptions()));
  os.flush();
  return os.str();
}

string rewrite_va_list(string str) {
  return regex_replace(str, std::regex("struct __va_list_tag \\*"), "va_list ");
}

#if 0
string type_to_str(QualType t, string place_holder="") {
  string ret;
  llvm::raw_string_ostream os(ret);
  t.print(os, PrintingPolicy(LangOptions()), place_holder);
  os.flush();
  string str = os.str();
  str = rewrite_anony(str);
  str = rewrite_va_list(str);
  return str;
}
#endif

std::string escape_string(std::string input) {
  // seems to be unefficient??
  std::string ret;
  for (auto it=input.begin(),end=input.end();it!=end;++it) {
    if (*it == '"') {
      ret += "\\\\\\\"";
    } else if (*it == '\\') {
      ret += "\\\\";
    } else if (*it == '\n') {
      ret += "\\\\n";
    } else if (*it == '\r') {
      ret += "\\\\r";
    } else if (*it == '\t') {
      ret += "\\\\t";
    } else {
      ret += *it;
    }
  }
  return ret;
}

Loc clang_range_to_loc(SourceRange range, SourceManager &mgr) {
  SourceLocation begin = range.getBegin();
  SourceLocation end = range.getEnd();
  end = Lexer::getLocForEndOfToken(end, 0, mgr, LangOptions());
  
  return Loc(mgr.getExpansionLineNumber(begin),
             mgr.getExpansionColumnNumber(begin),
             mgr.getExpansionLineNumber(end),
             mgr.getExpansionColumnNumber(end));
}

Sexp *parse_ArrayType(const ArrayType *at, SourceManager &mgr) {
  if (!at) return nullptr;
  StructSexp *ret = new StructSexp("type:array");
  QualType t = at->getElementType();
  ret->add(parse_QualType(t, mgr));
  if (const IncompleteArrayType *iat = dyn_cast<IncompleteArrayType>(at)) {
    ret->add(nullptr);
  } else if (const ConstantArrayType *cat = dyn_cast<ConstantArrayType>(at)) {
    uint64_t size = cat->getSize().getLimitedValue();
    // FIXME array size can be constant or expr.  In case of expr, I
    // need to recursive visit it.  However, a constant does not make
    // a valid ASTNode to visit.  I cannot use liter-int either,
    // because in program, this might be computed value
    //
    // ret->add(new SymbolSexp(std::to_string(size)));
    StructSexp *size_sexp = new StructSexp("expr:liter-int");
    size_sexp->add(new StringSexp(std::to_string(size)));
    ret->add(size_sexp);
  } else if (const VariableArrayType *va = dyn_cast<VariableArrayType>(at)) {
    Expr *s = va->getSizeExpr();
    ret->add(parse_Expr(s, mgr));
  } else {
    llvm::errs() << "HWarn: Unsupported Array type" << "\n";
    // FIXME leak
    return nullptr;
  }
  return ret;
}
Sexp *parse_BuiltinType(const BuiltinType *bt, SourceManager &mgr) {
  if (!bt) return nullptr;
  StructSexp *ret = new StructSexp("type:builtin");
  // string name = bt->getName().str();
  BuiltinType::Kind k = bt->getKind();
  string name;
  switch (k) {
    // unsigned
  case BuiltinType::Void: name="void"; break;
  case BuiltinType::Bool: name="bool"; break;
  case BuiltinType::UChar: name="unsigned char"; break;
  case BuiltinType::UShort: name="unsigned short"; break;
  case BuiltinType::UInt: name="unsigned int"; break;
  case BuiltinType::ULong: name="unsigned long"; break;
  case BuiltinType::ULongLong: name="unsigned long long"; break;
    // signed
  case BuiltinType::SChar: name="signed char"; break;
  case BuiltinType::Short: name="short"; break;
  case BuiltinType::Int: name="int"; break;
  case BuiltinType::Long: name="long"; break;
  case BuiltinType::LongLong: name="long long"; break;
    // implicit
  case BuiltinType::Char_U: name="char"; break;
  case BuiltinType::Char_S: name="char"; break;
    // floating
  case BuiltinType::Float: name="float"; break;
  case BuiltinType::Double: name="double"; break;
  case BuiltinType::LongDouble: name="long double"; break;
  default:
    llvm::errs() << "HWarn: Unsupported builtin type: " << bt->getName(PrintingPolicy(LangOptions())) << "\n";
    // assert(false);
  }
  ret->add(new StringSexp(name));
  return ret;
}
Sexp *parse_FunctionType(const FunctionType *ft, SourceManager &mgr) {
  if (!ft) return nullptr;
  StructSexp *ret = new StructSexp("type:func");
  QualType ret_type = ft->getReturnType();
  ret->add(parse_QualType(ret_type, mgr));
  ListSexp *param_sexps = new ListSexp();
  if (const FunctionProtoType *fpt = dyn_cast<FunctionProtoType>(ft)) {
    ArrayRef<QualType> params = fpt->getParamTypes();
    for (auto it=params.begin();it!=params.end();++it) {
      QualType t = *it;
      param_sexps->add(parse_QualType(t, mgr));
    }
  } else {
    // K&R
    llvm::errs() << "HWarn: FunctionUnProtoType" << "\n";
  }
  ret->add(param_sexps);
  return ret;
}
Sexp *parse_ParenType(const ParenType *pt, SourceManager &mgr) {
  if (!pt) return nullptr;
  // This seems to be around function pointer
  QualType inner = pt->getInnerType();
  StructSexp *ret = new StructSexp("type:paren");
  ret->add(parse_QualType(inner, mgr));
  return ret;
}
Sexp *parse_PointerType(const PointerType *pt, SourceManager &mgr) {
  if (!pt) return nullptr;
  StructSexp *ret = new StructSexp("type:pointer");
  ret->add(parse_QualType(pt->getPointeeType(), mgr));
  return ret;
}
Sexp *parse_ReferenceType(const ReferenceType *rt, SourceManager &mgr) {
  if (!rt) return nullptr;
  StructSexp *ret = new StructSexp("type:ref");
  ret->add(parse_QualType(rt->getPointeeType(), mgr));
  return ret;
}

string create_helium_tagname(TagDecl *decl) {
  // create a hash for the ADDRESS
  // Just use the address
  char buf[64];
  sprintf(buf, "%p", (void*)decl);
  string ret = buf;
  ret = "HELIUM_TAGNAME_"+ret;
  return ret;
}

Sexp *parse_TagType(const TagType *tt, SourceManager &mgr) {
  if (!tt) return nullptr;
  TagDecl *decl = tt->getDecl();
  
  string type;
  if (decl->isStruct()) type="struct";
  else if (decl->isUnion()) type="union";
  else if (decl->isEnum()) type="enum";
  else assert(false);
  StructSexp *ret = new StructSexp("type:" + type);
  
  string name = decl->getName().str();
  // ret->add(new StringSexp(type));
  // GIVE IT A NAME
  if (name.empty()) {
    // ret->add(nullptr);
    ret->add(new StringSexp(create_helium_tagname(decl)));
    // ret->add(new StringSexp(gen_anonymous_tag_name(decl, mgr)));
  } else {
    ret->add(new StringSexp(name));
  }
  return ret;
}
Sexp *parse_TypedefType(const TypedefType *tt, SourceManager &mgr) {
  if (!tt) return nullptr;
  StructSexp *ret = new StructSexp("type:typedef");
  TypedefNameDecl *decl = tt->getDecl();
  string name = decl->getName().str();
  ret->add(new StringSexp(name));
  return ret;
}

Sexp *parse_AdjustedType(const AdjustedType *at, SourceManager &mgr) {
  // adjusted by the semantic engine for arbitrary reason
  // e.g. an array function argument will be changed to pointer
  QualType orig = at->getOriginalType();
  // QualType adj = at->getAdjustedType();
  return parse_QualType(orig, mgr);
}
// Seems to be struct/union/enum, but more
Sexp *parse_ElaboratedType(const ElaboratedType *kt, SourceManager &mgr) {
  return parse_QualType(kt->desugar(), mgr);
}

// FIXME two typeof, with expr or type
Sexp *parse_TypeOfExprType(const TypeOfExprType *tof, SourceManager &mgr) {
  // typeof
  StructSexp *ret = new StructSexp("type:typeof");
  ret->add(parse_Expr(tof->getUnderlyingExpr(), mgr));
  return ret;
}
Sexp *parse_TypeOfType(const TypeOfType *tot, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("type:typeof");
  ret->add(parse_QualType(tot->getUnderlyingType(), mgr));
  return ret;
}

Sexp *parse_QualType(QualType t, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("type:qual");
  const Type *under = t.getTypePtr();
  if (!under) return nullptr;
  // qual
  Qualifiers qual = t.getLocalQualifiers();
  ListSexp *qual_sexp = new ListSexp();
  if (qual.hasConst()) {
    qual_sexp->add(new StringSexp("const"));
  }
  if (qual.hasVolatile()) {
    qual_sexp->add(new StringSexp("volatile"));
  }
  if (qual.hasRestrict()) {
    qual_sexp->add(new StringSexp("restrict"));
  }
  ret->add(qual_sexp);
  // under
  if (const ArrayType *at = dyn_cast<ArrayType>(under)) {
    ret->add(parse_ArrayType(at, mgr));
  } else if (const BuiltinType *bt = dyn_cast<BuiltinType>(under)) {
    ret->add(parse_BuiltinType(bt, mgr));
  } else if (const FunctionType *ft = dyn_cast<FunctionType>(under)) {
    ret->add(parse_FunctionType(ft, mgr));
  } else if (const ParenType *pt = dyn_cast<ParenType>(under)) {
    ret->add(parse_ParenType(pt, mgr));
  } else if (const PointerType *pt = dyn_cast<PointerType>(under)) {
    ret->add(parse_PointerType(pt, mgr));
  } else if (const ReferenceType *rt = dyn_cast<ReferenceType>(under)) {
    ret->add(parse_ReferenceType(rt, mgr));
  } else if (const TagType *tt = dyn_cast<TagType>(under)) {
    ret->add(parse_TagType(tt, mgr));
  } else if (const TypedefType *tt = dyn_cast<TypedefType>(under)) {
    ret->add(parse_TypedefType(tt, mgr));
  } else if (const AdjustedType *at = dyn_cast<AdjustedType>(under)) {
    ret->add(parse_AdjustedType(at, mgr));
  } else if (const ElaboratedType *kt = dyn_cast<ElaboratedType>(under)) {
    ret->add(parse_ElaboratedType(kt, mgr));
  } else if (const TypeOfExprType *tof = dyn_cast<TypeOfExprType>(under)) {
    ret->add(parse_TypeOfExprType(tof, mgr));
  } else if (const TypeOfType *tot = dyn_cast<TypeOfType>(under)) {
    ret->add(parse_TypeOfType(tot, mgr));
  } else {
    llvm::errs() << "HWarn: Unsupported type: "
      << under->getTypeClassName () << "\n";
    return nullptr;
  }
  return ret;
}



//////////////////////////////
// Expr
//////////////////////////////

Sexp* parse_ExprStmt(Expr *expr, SourceManager &mgr) {
  if (!expr) return nullptr;
  StructSexp *ret = new StructSexp("stmt:expr");
  ret->add(parse_Expr(expr, mgr));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}


Sexp* parse_VarDecl(VarDecl *var, SourceManager &mgr) {
  if (!var) return nullptr;
  if (var->isThisDeclarationADefinition() == VarDecl::DeclarationOnly) return nullptr;
  StructSexp *ret = new StructSexp("decl:var");
  QualType t = var->getType();
  string name = var->getName().str();
  Expr *init = var->getInit();
  StorageClass sc = var->getStorageClass();
  ListSexp *sc_sexp = new ListSexp();
  if (sc == SC_Static) {
    sc_sexp->add(new StringSexp("static"));
  }
  // sc
  ret->add(sc_sexp);
  // type
  ret->add(parse_QualType(t, mgr));
  // name
  ret->add(new StringSexp(name));
  // src
  // ret->add(new StringSexp(type_to_str(t, name)));
  // init
  ret->add(parse_Expr(init, mgr));
  ret->SetLoc(clang_range_to_loc(var->getSourceRange(), mgr));
  return ret;
}

// // [C99 6.5.2.4] Postfix increment and decrement
// UNARY_OPERATION(PostInc, "++")
// UNARY_OPERATION(PostDec, "--")
// // [C99 6.5.3.1] Prefix increment and decrement 
// UNARY_OPERATION(PreInc, "++")
// UNARY_OPERATION(PreDec, "--")
// // [C99 6.5.3.2] Address and indirection
// UNARY_OPERATION(AddrOf, "&")
// UNARY_OPERATION(Deref, "*")
// // [C99 6.5.3.3] Unary arithmetic 
// UNARY_OPERATION(Plus, "+")
// UNARY_OPERATION(Minus, "-")
// UNARY_OPERATION(Not, "~")
// UNARY_OPERATION(LNot, "!")
Sexp *parse_UnaryOperator(UnaryOperator *un, SourceManager &mgr) {
  Expr *sub = un->getSubExpr();
  StructSexp *ret = new StructSexp("expr:unary");
  UnaryOperatorKind op = un->getOpcode();
  string op_str;
  switch (op) {
  case UO_PostInc: op_str = "postinc"; break;
  case UO_PostDec: op_str = "postdec"; break;
  case UO_PreInc: op_str = "preinc"; break;
  case UO_PreDec: op_str = "predec"; break;
  case UO_AddrOf: op_str = "addrof"; break;
  case UO_Deref: op_str = "deref"; break;
  case UO_Plus: op_str = "plus"; break;
  case UO_Minus: op_str = "minus"; break;
  case UO_Not: op_str = "not"; break;
  case UO_LNot: op_str = "lnot"; break;
  case UO_Extension: op_str="__extension__"; break;
  default:
    llvm::errs() << "HWarn: Unsupported UnaryOperator opcode: " << UnaryOperator::getOpcodeStr(op) << "\n";
  }
  ret->add(new StringSexp(op_str));
  ret->add(parse_Expr(sub, mgr));
  ret->SetLoc(clang_range_to_loc(un->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_BinaryOperator(BinaryOperator *bi, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("expr:binary");
  BinaryOperatorKind op = bi->getOpcode();
  string op_str;
  switch (op) {
    // [C++ 5.5] Pointer-to-member operators.
  case BO_PtrMemD: op_str = "."; break;
  case BO_PtrMemI: op_str = "->"; break;
    // [C99 6.5.5] Multiplicative operators.
  case BO_Mul: op_str = "*"; break;
  case BO_Div: op_str = "/"; break;
  case BO_Rem: op_str = "%"; break;
    // [C99 6.5.6] Additive operators.
  case BO_Add: op_str = "+"; break;
  case BO_Sub: op_str = "-"; break;
    // [C99 6.5.7] Bitwise shift operators.
  case BO_Shl: op_str = "<<"; break;
  case BO_Shr: op_str = ">>"; break;
    // [C99 6.5.8] Relational operators.
  case BO_LT: op_str = "<"; break;
  case BO_GT: op_str = ">"; break;
  case BO_LE: op_str = "<="; break;
  case BO_GE: op_str = ">="; break;
    // [C99 6.5.9] Equality operators.
  case BO_EQ: op_str = "=="; break;
  case BO_NE: op_str = "!="; break;
    // [C99 6.5.10] Bitwise AND operator.
  case BO_And: op_str = "&"; break;
    // [C99 6.5.11] Bitwise XOR operator.
  case BO_Xor: op_str = "^"; break;
    // [C99 6.5.12] Bitwise OR operator.
  case BO_Or: op_str = "|"; break;
    // [C99 6.5.13] Logical AND operator.
  case BO_LAnd: op_str = "&&"; break;
    // [C99 6.5.14] Logical OR operator.
  case BO_LOr: op_str = "||"; break;
    // [C99 6.5.16] Assignment operators.
  case BO_Assign: op_str = "="; break;
  case BO_MulAssign: op_str = "*="; break;
  case BO_DivAssign: op_str = "/="; break;
  case BO_RemAssign: op_str = "%="; break;
  case BO_AddAssign: op_str = "+="; break;
  case BO_SubAssign: op_str = "-="; break;
  case BO_ShlAssign: op_str = "<<="; break;
  case BO_ShrAssign: op_str = ">>="; break;
  case BO_AndAssign: op_str = "&="; break;
  case BO_XorAssign: op_str = "^="; break;
  case BO_OrAssign: op_str = "|="; break;
    // // [C99 6.5.17] Comma operator.
  case BO_Comma: op_str = ","; break;
  default: assert(false);
  }
  Expr *lhs = bi->getLHS();
  Expr *rhs = bi->getRHS();
  ret->add(new StringSexp(op_str));
  ret->add(parse_Expr(lhs, mgr));
  ret->add(parse_Expr(rhs, mgr));
  ret->SetLoc(clang_range_to_loc(bi->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_CallExpr(CallExpr *call, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("expr:call");
  Expr *callee = call->getCallee();

  ret->add(parse_Expr(callee, mgr));

  
  ListSexp *args = new ListSexp();
  for (auto it=call->arg_begin();it!=call->arg_end();++it) {
    clang::Expr *arg = *it;
    args->add(parse_Expr(arg, mgr));
  }
  ret->add(args);
  ret->SetLoc(clang_range_to_loc(call->getSourceRange(), mgr));
  return ret;
}



Sexp *parse_CastExpr(CastExpr *cast, SourceManager &mgr) {
  Expr *sub = cast->getSubExpr();
  Sexp *sub_sexp = parse_Expr(sub, mgr);
  if (ExplicitCastExpr *e_cast = dyn_cast<ExplicitCastExpr>(cast)) {
    QualType t = e_cast->getTypeAsWritten();
    Sexp *to_type = parse_QualType(t, mgr);
    StructSexp *ret = new StructSexp("expr:cast");
    ret->add(to_type);
    ret->add(sub_sexp);
    ret->SetLoc(clang_range_to_loc(cast->getSourceRange(), mgr));
    return ret;
  } else {
    return sub_sexp;
  }
}
Sexp *parse_ParenExpr(ParenExpr *paren, SourceManager &mgr) {
  Expr *sub = paren->getSubExpr();
  StructSexp *ret = new StructSexp("expr:paren");
  ret->add(parse_Expr(sub, mgr));
  ret->SetLoc(clang_range_to_loc(paren->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_DeclRefExpr(DeclRefExpr *ref, SourceManager &mgr) {
  ValueDecl *decl = ref->getDecl();
  // StructSexp *ret = new StructSexp("expr:declref");
  if (VarDecl *inner = dyn_cast<VarDecl>(decl)) {
    string name = inner->getName().str();
    StructSexp *ret = new StructSexp("expr:ref-var");
    ret->add(new StringSexp(name));
    ret->SetLoc(clang_range_to_loc(ref->getSourceRange(), mgr));
    return ret;
  } else if (EnumConstantDecl *inner = dyn_cast<EnumConstantDecl>(decl)) {
    string name = inner->getName().str();
    StructSexp *ret = new StructSexp("expr:ref-enum-const");
    ret->add(new StringSexp(name));
    ret->SetLoc(clang_range_to_loc(ref->getSourceRange(), mgr));
    return ret;
  } else if (FunctionDecl *inner = dyn_cast<FunctionDecl>(decl)) {
    string name = inner->getName().str();
    StructSexp *ret = new StructSexp("expr:ref-func");
    ret->add(new StringSexp(name));
    ret->SetLoc(clang_range_to_loc(ref->getSourceRange(), mgr));
    return ret;
  } else {
    llvm::errs() << "HWarn: not supported DeclRefExpr: " << decl->getDeclKindName() << "\n";
    return nullptr;
  }
}
Sexp *parse_MemberExpr(MemberExpr *mem, SourceManager &mgr) {
  Expr *base = mem->getBase();
  StructSexp *ret = new StructSexp("expr:member");
  ret->add(parse_Expr(base, mgr));

  if (mem->isArrow()) {
    ret->add(new StringSexp("->"));
  } else {
    ret->add(new StringSexp("."));
  }

  string member = mem->getMemberDecl()->getName().str();
  ret->add(new StringSexp(member));
  ret->SetLoc(clang_range_to_loc(mem->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_AbstractConditionalOperator(AbstractConditionalOperator *cond_expr, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("expr:ternary");
  Expr *cond = cond_expr->getCond();
  Expr *t = cond_expr->getTrueExpr();
  Expr *f = cond_expr->getFalseExpr();
  ret->add(parse_Expr(cond, mgr));
  ret->add(parse_Expr(t, mgr));
  ret->add(parse_Expr(f, mgr));
  ret->SetLoc(clang_range_to_loc(cond_expr->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_ArraySubscriptionExpr(ArraySubscriptExpr *array_sub, SourceManager &mgr) {
  Expr *lhs = array_sub->getLHS();
  Expr *rhs = array_sub->getRHS();
  StructSexp *ret = new StructSexp("expr:array");
  ret->add(parse_Expr(lhs, mgr));
  ret->add(parse_Expr(rhs, mgr));
  ret->SetLoc(clang_range_to_loc(array_sub->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_IntegerLiteral(IntegerLiteral *expr, SourceManager &mgr) {
  uint64_t value = expr->getValue().getLimitedValue();
  StructSexp *ret = new StructSexp("expr:liter-int");
  ret->add(new StringSexp(std::to_string(value)));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_CharacterLiteral(CharacterLiteral *expr, SourceManager &mgr) {
  char c = expr->getValue();
  StructSexp *ret = new StructSexp("expr:liter-char");
  ret->add(new StringSexp(std::to_string(c)));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_FloatingLiteral(FloatingLiteral *expr, SourceManager &mgr) {
  float value = expr->getValue().convertToFloat();
  StructSexp *ret = new StructSexp("expr:liter-float");
  ret->add(new StringSexp(std::to_string(value)));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_StringLiteral(StringLiteral *expr, SourceManager &mgr) {
  string str = expr->getString().str();
  // str = escape_string(str);
  // str = '"' + str + '"';
  // std::cout << "... " << str << "\n";
  StructSexp *ret = new StructSexp("expr:liter-str");
  ret->add(new StringSexp(str));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_InitListExpr(InitListExpr *expr, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("expr:init-list");
  ArrayRef<Expr*> inits = expr->inits();
  ListSexp *tmp = new ListSexp();
  // There will be as many fields as these inits, even if the init
  // list is not that much. Those will be #f
  for (auto it=inits.begin();it!=inits.end();++it) {
    Expr *e = *it;
    tmp->add(parse_Expr(e, mgr));
  }
  ret->add(tmp);
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_VAArgExpr(VAArgExpr *expr, SourceManager &mgr) {
  // a call to __builtin_va_arg
  StructSexp *ret = new StructSexp("expr:vaarg");
  Expr *sub = expr->getSubExpr();
  ret->add(parse_Expr(sub, mgr));

  TypeSourceInfo *info = expr->getWrittenTypeInfo();
  QualType t = info->getType();
  ret->add(parse_QualType(t, mgr));
  
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_UnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *expr, SourceManager &mgr) {
  // sizeof/alignof
  string kind;
  switch (expr->getKind()) {
  case UETT_SizeOf: kind="sizeof"; break;
  case UETT_AlignOf: kind="alignof"; break;
  default: assert("false");
  }
  StructSexp *ret = new StructSexp("expr:"+kind);
  // FIXME express this alternation in racket
  // FIXME whether this alternation corresponds to above kind
  if (expr->isArgumentType()) {
    QualType t = expr->getArgumentType();
    ret->add(parse_QualType(t, mgr));
  } else {
    Expr *e = expr->getArgumentExpr();
    ret->add(parse_Expr(e, mgr));
  }
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_StmtExpr(StmtExpr *expr, SourceManager &mgr) {
  // GNU statement expression extension: {int X=4; X;}
  // It is a single comp_stmt, and evaluates to the last subexpression
  CompoundStmt *comp = expr->getSubStmt();
  StructSexp *ret = new StructSexp("expr:stmt");
  ret->add(parse_CompoundStmt(comp, mgr));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}

// Sexp *parse_OffsetOfNode(const OffsetOfNode& node, SourceManager &mgr) {
//   StructSexp *ret = new StructSexp("helper:offsetofnode");
//   switch (node.getKind()) {
//   case OffsetOfNode::Array: {
//     unsigned idx = node.getArrayExprIndex();
//     ret->add(new SymbolSexp("array"));
//     ret->add(new StringSexp(std::to_string(idx)));
//     break;
//   }
//   case OffsetOfNode::Field: {
//     string name = node.getField()->getName().str();
//     ret->add(new SymbolSexp("field"));
//     ret->add(new StringSexp(name));
//     break;
//   }
//   case OffsetOfNode::Identifier: {
//     string name = node.getFieldName()->getName().str();
//     ret->add(new SymbolSexp("field"));
//     ret->add(new StringSexp(name));
//     break;
//   }
//   default: assert(false);
//   }
//   return ret;
// }

Sexp *parse_OffsetOfExpr(OffsetOfExpr *expr, SourceManager &mgr) {
  // This is offsetof(record-type, member-designator)
  // e.g. offsetof(struct T, s[2].d)
  StructSexp *ret = new StructSexp("expr:offsetof");

  ret->add(new StringSexp(stmt_to_str(expr)));

  #if 0
  QualType t = expr->getTypeSourceInfo()->getType();
  ret->add(parse_QualType(t, mgr));
  unsigned num_comp = expr->getNumComponents();
  unsigned num_expr = expr->getNumExpressions();
  ListSexp *node_sexps = new ListSexp();
  for (int i=0;i<num_comp;i++) {
    const OffsetOfNode &node = expr->getComponent(i);
    node_sexps->add(parse_OffsetOfNode(node, mgr));
  }
  ListSexp *expr_sexps = new ListSexp();
  for (int i=0;i<num_expr;i++) {
    Expr *e = expr->getIndexExpr(i);
    expr_sexps->add(parse_Expr(e, mgr));
  }
  ret->add(node_sexps);
  ret->add(expr_sexps);
  #endif
  
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_CompoundLiteralExpr(CompoundLiteralExpr *expr, SourceManager &mgr) {
  // C99 6.5.2.5
  Expr *init = expr->getInitializer();
  StructSexp *ret = new StructSexp("expr:liter-comp");
  ret->add(parse_Expr(init, mgr));
  ret->SetLoc(clang_range_to_loc(expr->getSourceRange(), mgr));
  return ret;
}

Sexp *parse_PredefinedExpr(PredefinedExpr *expr, SourceManager &mgr) {
  if (!expr) return nullptr;
  StringLiteral *liter = expr->getFunctionName();
  assert(liter);
  // string str = liter->getString().str();
  // **DEBUG_START** //
  // string str = PredefinedExpr::getIdentTypeName(expr->getIdentType()).str();
  // **DEBUG_STOP** //
  string str = PredefinedExpr::getIdentKindName(expr->getIdentKind()).str();
  StructSexp *ret = new StructSexp("expr:predefined");
  ret->add(new StringSexp(str));
  return ret;
}

Sexp *gen_DummyExpr(std::string str, Expr *expr, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("expr:dummy");
  ret->add(new StringSexp(str));
  ret->add(new StringSexp(stmt_to_str(expr)));
  return ret;
}

Sexp* parse_Expr(Expr *expr, SourceManager &mgr) {
  if (!expr) return nullptr;
  if (DeclRefExpr *ref = dyn_cast<DeclRefExpr>(expr)) {
    return parse_DeclRefExpr(ref, mgr);
  } else if (UnaryOperator *un = dyn_cast<UnaryOperator>(expr)) {
    return parse_UnaryOperator(un, mgr);
  } else if (BinaryOperator *bi = dyn_cast<BinaryOperator>(expr)) {
    return parse_BinaryOperator(bi, mgr);
  } else if (CallExpr *call = dyn_cast<CallExpr>(expr)) {
    return parse_CallExpr(call, mgr);
  } else if (CastExpr *cast = dyn_cast<CastExpr>(expr)) {
    return parse_CastExpr(cast, mgr);
  } else if (ParenExpr *paren = dyn_cast<ParenExpr>(expr)) {
    return parse_ParenExpr(paren, mgr);
  } else if (MemberExpr *mem = dyn_cast<MemberExpr>(expr)) {
    return parse_MemberExpr(mem, mgr);
  } else if (AbstractConditionalOperator *cond_expr = dyn_cast<AbstractConditionalOperator>(expr)) {
    return parse_AbstractConditionalOperator(cond_expr, mgr);
  } else if (IntegerLiteral *liter = dyn_cast<IntegerLiteral>(expr)) {
    return parse_IntegerLiteral(liter, mgr);
  } else if (StringLiteral *liter = dyn_cast<StringLiteral>(expr)) {
    return parse_StringLiteral(liter, mgr);
  } else if (ArraySubscriptExpr *array_sub = dyn_cast<ArraySubscriptExpr>(expr)) {
    return parse_ArraySubscriptionExpr(array_sub, mgr);
  } else if (CharacterLiteral *cl = dyn_cast<CharacterLiteral>(expr)) {
    return parse_CharacterLiteral(cl, mgr);
  } else if (InitListExpr *init = dyn_cast<InitListExpr>(expr)) {
    return parse_InitListExpr(init, mgr);
  } else if (VAArgExpr *va = dyn_cast<VAArgExpr>(expr)) {
    return parse_VAArgExpr(va, mgr);
  } else if (UnaryExprOrTypeTraitExpr *szof = dyn_cast<UnaryExprOrTypeTraitExpr>(expr)) {
    return parse_UnaryExprOrTypeTraitExpr(szof, mgr);
  } else if (StmtExpr *stmt_expr = dyn_cast<StmtExpr>(expr)) {
    return parse_StmtExpr(stmt_expr, mgr);
  } else if (OffsetOfExpr *offset = dyn_cast<OffsetOfExpr>(expr)) {
    // C99 7.17
    return parse_OffsetOfExpr(offset, mgr);
  } else if (FloatingLiteral *fl = dyn_cast<FloatingLiteral>(expr)) {
    return parse_FloatingLiteral(fl, mgr);
  } else if (CompoundLiteralExpr *cl = dyn_cast<CompoundLiteralExpr>(expr)) {
    return parse_CompoundLiteralExpr(cl, mgr);
  } else if (ImplicitValueInitExpr *im = dyn_cast<ImplicitValueInitExpr>(expr)) {
    // This really just nothing
    return nullptr;
  } else if (PredefinedExpr *pe = dyn_cast<PredefinedExpr>(expr)) {
    // C99 6.4.2.2
    // it seems to be an identifier, e.g. __func__
    return parse_PredefinedExpr(pe, mgr);
    return nullptr;
  } else if (TypeTraitExpr *tte = dyn_cast<TypeTraitExpr>(expr)) {
    // TODO this seems to be C++11, but linux has it
    return gen_DummyExpr("typetraitexpr", tte, mgr);
  } else if (ChooseExpr *ce = dyn_cast<ChooseExpr>(expr)) {
    // TODO GCC extension __builtin_choose_expr
    return gen_DummyExpr("ChooseExpr", ce, mgr);
  } else if (OpaqueValueExpr *ov = dyn_cast<OpaqueValueExpr>(expr)) {
    // TODO This seems to be the middle component of a BinaryConditionalOperator
    return gen_DummyExpr("OpaqueValueExpr", ov, mgr);
  } else if (AddrLabelExpr *ale = dyn_cast<AddrLabelExpr>(expr)) {
    // TODO GNU address of label expression, &&label
    return gen_DummyExpr("AddrLabelExpr", ale, mgr);
  // } else if () {
  // } else if () {
  // } else if () {
  } else {
    llvm::errs() << "HWarn: Unsupported Expr: " << expr->getStmtClassName() << "\n";
    return nullptr;
  }
}

Sexp* parse_DeclStmt(DeclStmt *decl_stmt, SourceManager &mgr) {
  if (!decl_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:decl");

  ListSexp *tmp = new ListSexp();
  for (auto it=decl_stmt->decl_begin();it!=decl_stmt->decl_end();++it) {
    Decl *decl = *it;
    // if (clang::VarDecl *vardecl = dyn_cast<VarDecl>(decl)) {
    //   Sexp *sexp = parse_VarDecl(vardecl);
    //   tmp->add(sexp);
    // } else {
    //   llvm::errs() << "HWarn: DeclStmt not a var, but " << decl->
    // }
    tmp->add(parse_Decl(decl, mgr));
  }
  ret->add(tmp);
  return ret;
}





Sexp *parse_EmptyDecl(EmptyDecl *empty, SourceManager &mgr) {
  // This contains semicolon!!
  // This should be inside for() I guess
  StructSexp *ret = new StructSexp("decl:empty");
  ret->SetLoc(clang_range_to_loc(empty->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_FileScopeAsmDecl(FileScopeAsmDecl *decl, SourceManager &mgr) {
  string s = decl->getAsmString()->getString().str();
  StructSexp *ret = new StructSexp("decl:asm");
  ret->add(new StringSexp(s));
  ret->SetLoc(clang_range_to_loc(decl->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_Decl(Decl *decl, SourceManager &mgr) {
  if (!decl) return nullptr;
  if (FunctionDecl *func = dyn_cast<FunctionDecl>(decl)) {
    return parse_FunctionDecl(func, mgr);
  } else if (LabelDecl *label = dyn_cast<LabelDecl>(decl)) {
    return parse_LabelDecl(label, mgr);
  } else if (EnumDecl *enum_decl = dyn_cast<EnumDecl>(decl)) {
    return parse_EnumDecl(enum_decl, mgr);
  } else if (RecordDecl *record = dyn_cast<RecordDecl>(decl)) {
    return parse_RecordDecl(record, mgr);
  } else if (TypedefNameDecl *type = dyn_cast<TypedefNameDecl>(decl)) {
    return parse_TypedefNameDecl(type, mgr);
  } else if (VarDecl *var = dyn_cast<VarDecl>(decl)) {
    return parse_VarDecl(var, mgr);
  } else if (EmptyDecl *empty = dyn_cast<EmptyDecl>(decl)) {
    return parse_EmptyDecl(empty, mgr);
  } else if (FileScopeAsmDecl *asm_decl = dyn_cast<FileScopeAsmDecl>(decl)) {
    return parse_FileScopeAsmDecl(asm_decl, mgr);
  } else {
    string name = decl->getDeclKindName();
    llvm::errs() << "HWarn: Decl of kind " << name << " not supported." << "\n";
    return nullptr;
  }
}


Sexp* parse_CompoundStmt(CompoundStmt *comp, SourceManager &mgr) {
  if (!comp) return nullptr;
  StructSexp *ret = new StructSexp("stmt:comp");
  ListSexp *tmp = new ListSexp();
  for (auto it=comp->body_begin();it!=comp->body_end();it++) {
    Stmt *stmt = *it;
    tmp->add(parse_Stmt(stmt, mgr));
  }
  ret->add(tmp);
  ret->SetLoc(clang_range_to_loc(comp->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_IfStmt(IfStmt *if_stmt, SourceManager &mgr) {
  if (!if_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:if");
  Expr *cond = if_stmt->getCond();
  Stmt *then = if_stmt->getThen();
  Stmt *els = if_stmt->getElse();
  ret->add(parse_Expr(cond, mgr));
  ret->add(parse_Stmt(then, mgr));
  ret->add(parse_Stmt(els, mgr));
  ret->SetLoc(clang_range_to_loc(if_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_CaseStmt(CaseStmt *stmt, SourceManager &mgr) {
  if (!stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:case");
  Expr *lhs = stmt->getLHS();
  ret->add(parse_Expr(lhs, mgr));
  Stmt *sub = stmt->getSubStmt();
  ret->add(parse_Stmt(sub, mgr));
  ret->SetLoc(clang_range_to_loc(stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_DefaultStmt(DefaultStmt *stmt, SourceManager &mgr) {
  if (!stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:default");
  Stmt *sub = stmt->getSubStmt();
  ret->add(parse_Stmt(sub, mgr));
  ret->SetLoc(clang_range_to_loc(stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_SwitchStmt(SwitchStmt *switch_stmt, SourceManager &mgr) {
  if (!switch_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:switch");
  Expr *cond = switch_stmt->getCond();
  ret->add(parse_Expr(cond, mgr));

  // using body only
  ret->add(parse_Stmt(switch_stmt->getBody(), mgr));
  ret->SetLoc(clang_range_to_loc(switch_stmt->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_ForStmt(ForStmt *for_stmt, SourceManager &mgr) {
  if (!for_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:for");
  Stmt *init = for_stmt->getInit();
  Expr *cond = for_stmt->getCond();
  Expr *inc = for_stmt->getInc();
  Stmt *body = for_stmt->getBody();
  ret->add(parse_Stmt(init, mgr));
  ret->add(parse_Expr(cond, mgr));
  ret->add(parse_Expr(inc, mgr));
  ret->add(parse_Stmt(body, mgr));
  ret->SetLoc(clang_range_to_loc(for_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_DoStmt(DoStmt *do_stmt, SourceManager &mgr) {
  if (!do_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:do");
  Expr *cond = do_stmt->getCond();
  Stmt *body = do_stmt->getBody();
  ret->add(parse_Stmt(body, mgr));
  ret->add(parse_Expr(cond, mgr));
  ret->SetLoc(clang_range_to_loc(do_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_WhileStmt(WhileStmt *while_stmt, SourceManager &mgr) {
  if (!while_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:while");
  Expr *cond = while_stmt->getCond();
  Stmt *body = while_stmt->getBody();
  ret->add(parse_Expr(cond, mgr));
  ret->add(parse_Stmt(body, mgr));
  ret->SetLoc(clang_range_to_loc(while_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_BreakStmt(BreakStmt *break_stmt, SourceManager &mgr) {
  if (!break_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:break");
  ret->SetLoc(clang_range_to_loc(break_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_ContinueStmt(ContinueStmt *cont, SourceManager &mgr) {
  if (!cont) return nullptr;
  StructSexp *ret = new StructSexp("stmt:cont");
  ret->SetLoc(clang_range_to_loc(cont->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_ReturnStmt(ReturnStmt *ret_stmt, SourceManager &mgr) {
  if (!ret_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:return");
  Expr *expr = ret_stmt->getRetValue();
  if (expr) {
    ret->add(parse_Expr(expr, mgr));
  } else {
    ret->add(nullptr);
  }
  ret->SetLoc(clang_range_to_loc(ret_stmt->getSourceRange(), mgr));
  return ret;
}


Sexp* parse_NullStmt(NullStmt *null_stmt, SourceManager &mgr) {
  StructSexp *ret = new StructSexp("stmt:null");
  ret->SetLoc(clang_range_to_loc(null_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_GCCAsmStmt(GCCAsmStmt *asm_stmt, SourceManager &mgr) {
  StringLiteral *sl = asm_stmt->getAsmString();
  assert(sl);
  string str = sl->getString().str();
  StructSexp *ret = new StructSexp("stmt:asm");
  ret->add(new StringSexp(str));
  ret->SetLoc(clang_range_to_loc(asm_stmt->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_Stmt(Stmt *stmt, SourceManager &mgr) {
  if (!stmt) return nullptr;
  if (DeclStmt *decl_stmt = dyn_cast<DeclStmt>(stmt)) {
    return parse_DeclStmt(decl_stmt, mgr);
  } else if (CompoundStmt *comp = dyn_cast<CompoundStmt>(stmt)) {
    return parse_CompoundStmt(comp, mgr);
  } else if (IfStmt *if_stmt = dyn_cast<IfStmt>(stmt)) {
    return parse_IfStmt(if_stmt, mgr);
  } else if (SwitchStmt *switch_stmt = dyn_cast<SwitchStmt>(stmt)) {
    return parse_SwitchStmt(switch_stmt, mgr);
  } else if (CaseStmt *case_stmt = dyn_cast<CaseStmt>(stmt)) {
    return parse_CaseStmt(case_stmt, mgr);
  } else if (DefaultStmt *default_stmt = dyn_cast<DefaultStmt>(stmt)) {
    return parse_DefaultStmt(default_stmt, mgr);
  } else if (ForStmt *for_stmt = dyn_cast<ForStmt>(stmt)) {
    return parse_ForStmt(for_stmt, mgr);
  } else if (DoStmt *do_stmt = dyn_cast<DoStmt>(stmt)) {
    return parse_DoStmt(do_stmt, mgr);
  } else if (WhileStmt *while_stmt = dyn_cast<WhileStmt>(stmt)) {
    return parse_WhileStmt(while_stmt, mgr);
  } else if (BreakStmt *break_stmt = dyn_cast<BreakStmt>(stmt)) {
    return parse_BreakStmt(break_stmt, mgr);
  } else if (ContinueStmt *cont_stmt = dyn_cast<ContinueStmt>(stmt)) {
    return parse_ContinueStmt(cont_stmt, mgr);
  } else if (ReturnStmt *ret_stmt = dyn_cast<ReturnStmt>(stmt)) {
    return parse_ReturnStmt(ret_stmt, mgr);
  } else if (NullStmt *null_stmt = dyn_cast<NullStmt>(stmt)) {
    return parse_NullStmt(null_stmt, mgr);
  } else if (GCCAsmStmt *asm_stmt = dyn_cast<GCCAsmStmt>(stmt)) {
    return parse_GCCAsmStmt(asm_stmt, mgr);
  } else if (Expr *expr = dyn_cast<Expr>(stmt)) {
    return parse_ExprStmt(expr, mgr);
  } else if (GotoStmt *goto_stmt = dyn_cast<GotoStmt>(stmt)) {
    return parse_GotoStmt(goto_stmt, mgr);
  } else if (LabelStmt *label_stmt = dyn_cast<LabelStmt>(stmt)) {
    return parse_LabelStmt(label_stmt, mgr);
  } else {
    std::string name = stmt->getStmtClassName();
    llvm::errs() << "HWarn: Error: Stmt of kind " << name << " not supported." << "\n";
    return nullptr;
  }
}

Sexp *parse_GotoStmt(GotoStmt *goto_stmt, SourceManager &mgr) {
  if (!goto_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:goto");
  LabelDecl *label = goto_stmt->getLabel();
  // ret->add(parse_LabelDecl(label, mgr));
  string str = label->getName().str();
  ret->add(new StringSexp(str));
  
  // ret->add(new StringSexp(label->getName().str()));
  ret->SetLoc(clang_range_to_loc(goto_stmt->getSourceRange(), mgr));
  return ret;
}
Sexp *parse_LabelStmt(LabelStmt *label_stmt, SourceManager &mgr) {
  if (!label_stmt) return nullptr;
  StructSexp *ret = new StructSexp("stmt:label");
  // string name = label_stmt->getName();
  LabelDecl *label = label_stmt->getDecl();
  string str = label->getName().str();
  // ret->add(parse_LabelDecl(label, mgr));
  ret->add(new StringSexp(str));
  
  Stmt *sub = label_stmt->getSubStmt();
  ret->add(parse_Stmt(sub, mgr));

  ret->SetLoc(clang_range_to_loc(label_stmt->getSourceRange(), mgr));
  return ret;
}

Optional<Token> findNextToken(SourceLocation Loc,
                                     const SourceManager &SM,
                                     const LangOptions &LangOpts) {
  if (Loc.isMacroID()) {
    if (!Lexer::isAtEndOfMacroExpansion(Loc, SM, LangOpts, &Loc))
      return None;
  }
  Loc = Lexer::getLocForEndOfToken(Loc, 0, SM, LangOpts);

  // Break down the source location.
  std::pair<FileID, unsigned> LocInfo = SM.getDecomposedLoc(Loc);

  // Try to load the file buffer.
  bool InvalidTemp = false;
  StringRef File = SM.getBufferData(LocInfo.first, &InvalidTemp);
  if (InvalidTemp)
    return None;

  const char *TokenBegin = File.data() + LocInfo.second;

  // Lex from the start of the given location.
  Lexer lexer(SM.getLocForStartOfFile(LocInfo.first), LangOpts, File.begin(),
              TokenBegin, File.end());
  // Find the token.
  Token Tok;
  lexer.LexFromRawLexer(Tok);
  return Tok;
}


#if 0
/**
 * the FunctionDecl class does not provide API for getting function
 * name SourceLocation. I'm going to use a hack to get the next
 * token from Lexer
 * Token kinds from /usr/include/clang/Basic/TokenKinds.def
 *
 * This still not working
 * SourceLocation name_loc
 *   = Lexer::findLocationAfterToken(ret_range.getEnd(),
 *                                   tok::identifier, mgr, LangOptions(), true);
 * 
 * Now this is a super hacky hack. Clang has findNextToken, but didn't
 * expose it. I *copied* it here.
 */
Sexp* create_next_token(SourceManager &mgr, SourceLocation loc, unsigned offset) {
  assert(offset>0);
  while (offset--) {
    Optional<Token> token = findNextToken(loc, mgr, LangOptions());
    if (!token) {
      // this is very likely to be caused by Macro expansion
      return nullptr;
    }
    loc = token->getLocation();
  }
  // inside the get_source and create_token, the end loc will be
  // converted by getLocForEndOfToken
  SourceRange range(loc, loc);
  string src = get_source(mgr, range);
  return create_token(mgr, src, range);
}
#endif

Sexp* parse_FunctionDecl(FunctionDecl *func, SourceManager &mgr) {
  if (!func) return nullptr;
  if (!func->isThisDeclarationADefinition()) return nullptr;
  StructSexp *ret = new StructSexp("decl:func");

  ListSexp *sc_sexp = new ListSexp();
  StorageClass sc = func->getStorageClass();
  if (sc == SC_Static) {
    sc_sexp->add(new StringSexp("static"));
  }
  ret->add(sc_sexp);
  
  QualType t = func->getReturnType();
  ret->add(parse_QualType(t, mgr));

  string name = func->getName().str();
  ret->add(new StringSexp(name));

  ListSexp *tmp = new ListSexp();
  for (auto it=func->param_begin();it!=func->param_end();++it) {
    ParmVarDecl *param = *it;
    tmp->add(parse_VarDecl(param, mgr));
  }
  ret->add(tmp);
  
  Stmt *body = func->getBody();
  ret->add(parse_Stmt(body, mgr));

  if (func->isVariadic()) {
    ret->SetExtraAttr("variadic");
  }

  ret->SetLoc(clang_range_to_loc(func->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_LabelDecl(LabelDecl *label, SourceManager &mgr) {
  // should not be called. There are only two places that uses labels:
  // stmt:goto and stmt:label. In either case, I just get the label
  // name and continue.
  // label->dump();
  assert(label->isGnuLocal());
  // I'm not going to support it
  llvm::errs() << "Warning: parse_LabelDecl received a GNU local label." << "\n";
  return nullptr;
  // assert(false);
  if (!label) return nullptr;
  string name = label->getName().str();
  StructSexp *ret = new StructSexp("decl:label");
  ret->add(new StringSexp(name));
  ret->SetLoc(clang_range_to_loc(label->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_EnumConstantDecl(EnumConstantDecl *decl, SourceManager &mgr) {
  if (!decl) return nullptr;
  StructSexp *ret = new StructSexp("decl:enum-const");
  StringRef name = decl->getName();
  ret->add(new StringSexp(name.str()));

  Expr *init = decl->getInitExpr();
  if (init) {
    ret->add(parse_Expr(init, mgr));
  } else {
    ret->add(nullptr);
  }
  ret->SetLoc(clang_range_to_loc(decl->getSourceRange(), mgr));
  return ret;
}


Sexp* parse_EnumDecl(EnumDecl *decl, SourceManager &mgr) {
  if (!decl) return nullptr;
  StructSexp *ret = new StructSexp("decl:enum");
  string name = decl->getName().str();
  // if it does not have a name, it is either
  // - variable declarations
  // - typedef
  // in either case, we have another snippet for them
  // if (name.empty()) return nullptr;
  // if (decl->isEmbeddedInDeclarator ()) {
  //   return nullptr;
  // }
  if (name.empty()) {
    name=create_helium_tagname(decl);
    // name = gen_anonymous_tag_name(decl, mgr);
  }
  ret->add(new StringSexp(name));

  ListSexp *tmp = new ListSexp();
  for (auto it=decl->enumerator_begin();it!=decl->enumerator_end();++it) {
    EnumConstantDecl *member = *it;
    tmp->add(parse_EnumConstantDecl(member, mgr));
  }
  ret->add(tmp);
  ret->SetLoc(clang_range_to_loc(decl->getSourceRange(), mgr));
  return ret;
}
Sexp* parse_FieldDecl(FieldDecl *field, SourceManager &mgr) {
  if (!field) return nullptr;
  StructSexp *ret = new StructSexp("decl:record-field");
  
  QualType t = field->getType();
  ret->add(parse_QualType(t, mgr));
  
  StringRef name = field->getName();
  ret->add(new StringSexp(name.str()));
  // TODO isBitField
  ret->SetLoc(clang_range_to_loc(field->getSourceRange(), mgr));

  return ret;
}

/**
 * I should just return the string for it, it is tricky to construct,
 * when the struct has, e.g. function pointer
 */
Sexp* parse_RecordDecl(RecordDecl *record, SourceManager &mgr) {
  if (!record) return nullptr;
  if (!record->isThisDeclarationADefinition ()) return nullptr;
  string kind;
  if (record->isUnion()) {kind = "decl:union";}
  else if (record->isStruct()) {kind = "decl:struct";}
  else assert(false);
  StructSexp *ret = new StructSexp(kind);
  string name = record->getName().str();
  // if (record->isEmbeddedInDeclarator ()) {
  //   return nullptr;
  // }
  // if (name.empty()) return nullptr;
  if (name.empty()) {
    name = create_helium_tagname(record);
    // name = gen_anonymous_tag_name(record, mgr);
  }
  ret->add(new StringSexp(name));
  ListSexp *tmp = new ListSexp();
  for (auto it=record->field_begin();it!=record->field_end();++it) {
    FieldDecl *field = *it;
    tmp->add(parse_FieldDecl(field, mgr));
  }
  ret->add(tmp);
  ret->SetLoc(clang_range_to_loc(record->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_TypedefNameDecl(TypedefNameDecl *decl, SourceManager &mgr) {
  if (!decl) return nullptr;
  
  StructSexp *ret = new StructSexp("decl:typedef");
  ret->add(new StringSexp(decl->getNameAsString()));

  QualType t = decl->getUnderlyingType();
  ret->add(parse_QualType(t, mgr));
  
  ret->SetLoc(clang_range_to_loc(decl->getSourceRange(), mgr));
  return ret;
}

Sexp* parse_TranslationUnitDecl(TranslationUnitDecl *tu, SourceManager &mgr) {
  if (!tu) return nullptr;
  StructSexp *ret = new StructSexp("decl:tu");
  ListSexp *tmp = new ListSexp();
  for (auto it=tu->decls_begin(); it!=tu->decls_end();++it) {
    Decl *child = *it;
    if (mgr.isInMainFile(child->getLocation())) {
      tmp->add(parse_Decl(child, mgr));
    }
  }
  ret->add(tmp);
  
  ret->SetLoc(clang_range_to_loc(tu->getSourceRange(), mgr));
  return ret;
}


void process_tu(clang::TranslationUnitDecl *tu, clang::SourceManager &mgr) {
    FileID fid = mgr.getMainFileID();
    const FileEntry *entry = mgr.getFileEntryForID(fid);
    StringRef name = entry->getName();
    // llvm::errs() << "name: " << name << "\n";
    // this name is full path specified
    // *ADD* the extension .ss
    {
      Sexp *sexp = parse_TranslationUnitDecl(tu, mgr);
      
      ofstream of;
      string f = name.str() + ".ss";
      llvm::errs() << "==== Writing to " << f << "\n";
      of.open(f);
      sexp->dump(of);
      of.close();
    }

#if 0
    {
      // writing to XXX.he file
      string he = gen_he(tu, mgr);
      
      string f = name.str() + ".he";
      llvm::errs() << "==== Writing to " << f << "\n";
      ofstream of;
      of.open(f);
      of << he << "\n";
      of.close();
    }
#endif
}

bool is_point_within(SourceLocation Location,
                     SourceLocation Start,
                     SourceLocation End,
                     SourceManager &mgr) {
  return Location == Start || Location == End ||
    (mgr.isBeforeInTranslationUnit(Start, Location) &&
     mgr.isBeforeInTranslationUnit(Location, End));
}
string gen_inc(clang::TranslationUnitDecl *tu, clang::SourceManager &mgr) {
  std::vector<std::pair<std::string, SourceLocation> > incs;
  for (auto it=mgr.fileinfo_begin();it!=mgr.fileinfo_end();++it) {
    const FileEntry *entry = it->first;
    string real = entry->tryGetRealPathName().str();
    FileID id = mgr.translateFile(entry);
    SourceLocation loc = mgr.getIncludeLoc(id);
    // both the following  will be fine, but have different orders
    // if (mgr.isWrittenInMainFile(loc)) {
    if (mgr.isInMainFile(loc)) {
      // incs += real + "\n";
      incs.push_back(std::make_pair(real, loc));
    }
  }

  std::sort(incs.begin(), incs.end(),
            [](std::pair<std::string, SourceLocation> lhs,
               std::pair<std::string, SourceLocation> rhs) {
              return lhs.second.getRawEncoding() < rhs.second.getRawEncoding();
            });
  std::set<string> bad;
  for (auto p : incs) {
    for (auto it=tu->decls_begin(), end=tu->decls_end();
         it!=end;++it) {
      Decl *d = *it;
      // **DEBUG_START** //
      // if (is_point_within(p.second, d->getLocStart(), d->getLocEnd(), mgr)) {
      // **DEBUG_STOP** //
      if (is_point_within(p.second, d->getBeginLoc(), d->getEndLoc(), mgr)) {
        bad.insert(p.first);
        break;
      }
    }
  }
  string ret;
  for (auto p : incs) {
    if (bad.count(p.first) == 0) {
      ret += "#include \"" + p.first + "\"\n";
    }
  }
  return ret;
}


template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}
static std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

#if 0
// (anonymous enum at foo.c:36:1)
string rewrite_anony(string str) {
  size_t begin = str.find("(anonymous");
  if (begin != string::npos) {
    unsigned end = str.find(")", begin);
    string sub = str.substr(begin+1, end-begin-1);
    vector<string> v = split(sub, ' ');

    // std::cout << v.size() << "\n";
    // for (std::string s : v) {
    //   std::cout << s << "\n";
    // }
    assert(v.size() == 4);
    string name;
    name += "ANONYMOUS_";
    name += v[1];
    name += "_";
    string loc = v[3];
    std::replace(loc.begin(), loc.end(), '.', '_');
    std::replace(loc.begin(), loc.end(), ':', '_');
    std::replace(loc.begin(), loc.end(), '/', '_');
    std::replace(loc.begin(), loc.end(), '_', '_');
    std::replace(loc.begin(), loc.end(), '-', '_');
    name += loc;
    str.replace(begin, end-begin+1, name);
  }
  return str;
}

/**
 * foo_c_36_1
 */
string gen_loc_name(SourceLocation loc, SourceManager &mgr) {
  string ret;
  string f = mgr.getFilename(loc).str();
  std::replace(f.begin(), f.end(), '.', '_');
  std::replace(f.begin(), f.end(), ':', '_');
  std::replace(f.begin(), f.end(), '/', '_');
  std::replace(f.begin(), f.end(), '_', '_');
  std::replace(f.begin(), f.end(), '-', '_');
  unsigned col = mgr.getSpellingColumnNumber(loc);
  unsigned line = mgr.getSpellingLineNumber(loc);
  return f + "_" + std::to_string(line) + "_" + std::to_string(col);
}

string gen_anonymous_tag_name(TagDecl *tag, SourceManager &mgr) {
  string ret;
  ret = "ANONYMOUS_" + tag->getKindName().str()
    + "_" + gen_loc_name(tag->getLocation(), mgr);
  return ret;
}
#endif


#if 0
/**
 * Generate he_file by printing
 * 1. all decls
 * 2. static funcs
 * 3. declaration for non-static funcs
 */
string gen_he(clang::TranslationUnitDecl *tu,
            clang::SourceManager &mgr) {
  string ret;
  ret += gen_inc(tu, mgr);

  // special case
  ret += "#undef sa_handler\n";
  ret += "#undef sa_sigaction\n";
  // git config.c specific
  ret += "#undef config_error_nonbool\n";
  // git/parse-options.c
  ret += "#undef opterror\n";
  // git/usage.c
  ret += "#undef error_errno\n";
  ret += "#undef error\n";

  for (auto it=tu->decls_begin(), end=tu->decls_end();
       it!=end;++it) {
    Decl *d = *it;
    // va_arg function will produce an implicit function decl
    if (d->isImplicit()) continue;
    if (mgr.isInMainFile(d->getLocation())) {
      if (FunctionDecl *func = dyn_cast<FunctionDecl>(d)) {
        // for debugging purpose, I'm generating some comments
        // if (func->isImplicit()) {
        //   ret += "// implicit\n";
        // }
        string func_str = decl_to_str(func);
        if (func->isThisDeclarationADefinition()) {
          StorageClass sc = func->getStorageClass();
          if (sc == SC_Static) {
            ret += "// func static\n";
            ret += func_str + "\n";
          } else {
            // generate decl
            ret += "// func gen decl (DEBUG switching back to full decl cause of alias)\n";
            // ret += func_str.substr(0, func_str.find("{")) + ";\n";
            ret += func_str + ";\n";

            // ret += "// debug func\n";
            // ret += func_str + "\n";
              
          }
        } else {
          // FIXME this should just gives the decl
          ret += "// func decl\n";
          ret += func_str + ";\n";
        }
      } else if (VarDecl *var = dyn_cast<VarDecl>(d)) {
        ret += "// var\n";
        string var_str = decl_to_str(var);

        var_str = rewrite_anony(var_str);
        
        if (var->isThisDeclarationADefinition()) {
          StorageClass sc = var->getStorageClass();
          if (sc == SC_Static) {
            ret += var_str + ";\n";
          } else {
            // decl
            ret += "extern " + var_str + ";\n";
          }
        } else {
          ret += var_str + ";\n";
        }
      } else if (TagDecl *tag = dyn_cast<TagDecl>(d)) {
        ret += "// tag\n";
        string name = tag->getNameAsString();
        string str = decl_to_str(d);
        if (name.empty()) {
          name = gen_anonymous_tag_name(tag, mgr);
          ret += "// GIVEN name: " + name + "\n";
          str.insert(str.find('{'), name);
        }
        ret +=  str + ";\n";
      // } else if (RecordDecl *rec = dyn_cast<RecordDecl>(d)) {
      //   ret += "// record\n";
      //   if (rec->isAnonymousStructOrUnion()) {
      //     ret += "// Anony\n";
      //   }
      //   ret += decl_to_str(d) + ";\n";
      // } else if (EnumDecl *en = dyn_cast<EnumDecl>(d)) {
      //   ret += "// enum\n";
      //   ret += decl_to_str(d) + ";\n";
      } else if (TypedefNameDecl *tt = dyn_cast<TypedefNameDecl>(d)) {
        QualType under = tt->getUnderlyingType();
        const Type *tp = under.getTypePtr();
        if (tp && isa<ElaboratedType>(tp)
            && (tp = dyn_cast<ElaboratedType>(tp)->desugar().getTypePtr())
            && tp && isa<TagType>(tp)) {
          TagDecl *under_decl = dyn_cast<TagType>(tp)->getDecl();
          assert(under_decl);
          string name = under_decl->getName().str();
          if (name.empty()) {
            ret += "// rewritten typedef\n";
            string str = gen_anonymous_tag_name(under_decl, mgr);
            ret += "typedef " + under_decl->getKindName().str()
              + " " +  str + " "
              + tt->getNameAsString() + ";\n";
          } else {
            ret += "// typedef common 2\n";
            string str = decl_to_str(d);
            ret += str + ";\n";
          }
        } else {
          ret += "// typedef common 1\n";
          string str = decl_to_str(d);
          ret += str + ";\n";
        }
      } else {
        ret += "// other\n";
        string str = decl_to_str(d);
        ret += str + ";\n";
      }
    }
  }
  // ugly hack
  // std::replace(ret.begin, ret.end(), , "va_list");
  // return regex_replace(ret, std::regex("struct __va_list_tag \\*"), "va_list");
  return rewrite_va_list(ret);
  // return ret;
}


#endif
