#include <clang-c/CXCompilationDatabase.h>
#include <clang-c/Index.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h> // chdir

void print_cursor(CXCursor cursor) {
  CXString kind_str = clang_getCursorKindSpelling(clang_getCursorKind(cursor));

  CXTranslationUnit tu = clang_Cursor_getTranslationUnit(cursor);
  CXFile file = clang_getFile(tu, "test/a.c");
  if (!file) {
    printf("File is NULL\n");
  } else {
    printf("file found\n");
    CXString str = clang_getFileName(file);
    printf("name: %s\n", clang_getCString(str));
  }

  CXSourceLocation loc = clang_getCursorLocation(cursor);
  unsigned line, col;
  clang_getSpellingLocation(loc, file, &line, &col, NULL);

  CXSourceRange extent = clang_getCursorExtent(cursor);
  unsigned extent_start_line, extent_start_col;
  unsigned extent_end_line, extent_end_col;
  clang_getSpellingLocation(clang_getRangeStart(extent), file, &extent_start_line, &extent_start_col, NULL);
  clang_getSpellingLocation(clang_getRangeEnd(extent), file, &extent_end_line, &extent_end_col, NULL);
  
  printf("%s @ (%d:%d) extend (%d:%d-%d:%d)", clang_getCString(kind_str), line, col,
         extent_start_line, extent_start_col, extent_end_line, extent_end_col);
}

enum CXChildVisitResult visitor(CXCursor cursor, CXCursor parent, CXClientData data) {
  /* CXType type = clang_getCursorType(cursor); */
  /* CXString type_str = clang_getTypeSpelling(type); */
  /* printf("Type: %s\n", clang_getCString(type_str)); */

  /* CXString str = clang_getCursorSpelling(cursor); */
  /* printf("Cursor: %s\n", clang_getCString(str)); */
  CXTranslationUnit tu = clang_Cursor_getTranslationUnit(cursor);
  CXFile file = clang_getFile(tu, "test/a.c");
  if (!file) {
    printf("File is NULL\n");
    return CXChildVisit_Continue;
  } else {
    printf("file found\n");
    print_cursor(cursor);
    putchar(' ');
    print_cursor(parent);
    putchar('\n');
    return CXChildVisit_Recurse;
  }
}


CXTranslationUnit parse_file(char *filename) {
  CXIndex index = clang_createIndex(1,1);
  const char *args[] = {"-I", "/usr/lib/clang/5.0.1/include"};
  CXTranslationUnit tu = clang_parseTranslationUnit(index, filename,
                                                    /* NULL, 0, */
                                                    args, 2,
                                                    NULL, 0, 0);
  if (!tu) {
    printf("Error\n");
  } else {
    printf("TU created.\n");
  }
  return tu;
}
CXTranslationUnit parse_file_with_args(const char *file, const char **args, unsigned num_args) {
  printf("parsing %s\n", file);
  printf("num_args: %d\n", num_args);
  for (unsigned i=0;i<num_args;++i) {
    printf("%s ", args[i]);
  }
  printf("\n");
  CXIndex index = clang_createIndex(1,1);
  CXTranslationUnit tu = clang_parseTranslationUnit(index, file,
                                                           args, num_args,
                                                           NULL, 0, 0);
  if (!tu) {
    printf("Error\n");
  } else {
    printf("TU Created\n");
  }
  return tu;
}

CXTranslationUnit parse_file_with_argstr(const char *file, const char *argstr) {
  char args_str[strlen(argstr)+1];
  strcpy(args_str, argstr);
  char *tok = strtok(args_str, " ");
  const char *args[BUFSIZ];
  int num_args=0;
  while ((tok = strtok(NULL, " ")) != NULL) {
    args[num_args] = tok;
    num_args++;
  }
  return parse_file_with_args(file, args, num_args);
}

CXTranslationUnit parse_file_with_db(const char *bench_dir, const char *c_file) {
  CXCompilationDatabase db = clang_CompilationDatabase_fromDirectory(bench_dir, NULL);
  CXCompileCommands cmds = clang_CompilationDatabase_getCompileCommands(db, c_file);
  assert(clang_CompileCommands_getSize(cmds) == 1);
  printf("size of cmd: %d\n", clang_CompileCommands_getSize(cmds));
  CXCompileCommand cmd = clang_CompileCommands_getCommand(cmds, 0);
  unsigned num_args = clang_CompileCommand_getNumArgs(cmd);
  printf("Number of args: %d\n", num_args);
  if (num_args == 0) {
    printf("should not be 0. exiting\n");
    exit(1);
  }
  /* printf("Args: "); */
  const char *args[BUFSIZ];
  for (size_t i=0;i<num_args;i++) {
    /* args += clang_CompileCommand_getArg(cmd, i); */
    CXString cxstr = clang_CompileCommand_getArg(cmd, i);
    const char *arg = clang_getCString(cxstr);
    /* printf("%s ", arg); */
    /* strcat(args[i], arg); */
    args[i] = arg;
  }
  /* printf("\n"); */

  // -o xxx.o xxx.c
  // having those will cause invalid argument error
  return parse_file_with_args(c_file, args, num_args-3);
}



void visit(CXTranslationUnit tu) {
  CXCursor cursor = clang_getTranslationUnitCursor(tu);
  /* CXType type = clang_getCursorType(cursor); */
  /* CXString type_str = clang_getTypeSpelling(type); */
  /* printf("Type: %s\n", clang_getCString(type_str)); */
  printf("Visiting cursor\n");
  clang_visitChildren(cursor, visitor, NULL);
  printf("Done\n");
}

// not good for my usage
void tokenize(CXTranslationUnit tu) {
  CXToken *tokens;
  unsigned numTokens;
  /* CXSourceRange  */
  /* clang_tokenize(tu, range, tokens, numTokens); */
  CXCursor cursor = clang_getTranslationUnitCursor(tu);
  CXSourceRange range = clang_getCursorExtent(cursor);
  clang_tokenize(tu, range, &tokens, &numTokens);
  for (unsigned i=0;i<numTokens;i++) {
    CXToken tok = tokens[i];
    CXString str = clang_getTokenSpelling(tu, tok);
    printf("%s\n", clang_getCString(str));

    /* CXCursor *tmp_cursors; */
    /* clang_annotateTokens(tu, &tok, 1, &tmp) */
  }
}

void process_bench(const char *bench_dir, const char *file) {
  char buf[BUFSIZ];
  getcwd(buf, BUFSIZ);
  chdir(bench_dir);

  CXTranslationUnit tu = NULL;
  tu = parse_file_with_db(bench_dir, file);
  
  chdir(buf);
}

int main(int argc, char *argv[]) {
  // TODO read compilation database
  const char *bench_dir = "/home/hebi/Downloads/linux-4.14.9";
  const char *file = "/home/hebi/Downloads/linux-4.14.9/kernel/acct.c";


  /* process_bench(bench_dir, file); */

  CXTranslationUnit tu = NULL;
  tu = parse_file("test/a.c");
  visit(tu);
  /* tokenize(tu); */

  /* CXSourceLocation loc = clang_getLocation (tu, clang_getFile(tu, "test/a.c"), 8,8); */
  /* CXCursor cursor = clang_getCursor(tu, loc); */
  /* print_cursor(cursor); */
  /* putchar('\n'); */
  
  return 0;
}


