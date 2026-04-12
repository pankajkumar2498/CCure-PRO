try:
 ast.parse(open('Backend/core/models.py', 'r', encoding='utf-8').read())
except SyntaxError as e:
 traceback.print_exc()