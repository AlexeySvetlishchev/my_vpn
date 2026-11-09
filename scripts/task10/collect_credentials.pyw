"""Local Windows masked credential intake. Never echo credentials or IDs.

Run with pythonw. The only output file is outside the Git workspace and has a
user-only DACL. The agent may transfer the file but must never read its contents.
"""
import csv
import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tkinter as tk
from tkinter import messagebox
import re

def save(token,admin):
    if not re.fullmatch(r'[0-9]{5,15}:[A-Za-z0-9_-]{30,100}',token):
        raise ValueError('Неверный формат токена BotFather.')
    if not admin.isascii() or not admin.isdigit() or not 0<int(admin)<2**52:
        raise ValueError('Нужен положительный числовой Telegram user ID.')
    directory=Path(os.environ['LOCALAPPDATA'])/'vpn-ru-fr'/'task10'
    directory.mkdir(parents=True,exist_ok=True)
    for item in (directory.parent,directory):
        if item.is_symlink() or getattr(item.stat(),'st_file_attributes',0)&0x400:
            raise ValueError('Каталог передачи не должен быть ссылкой.')
    who=subprocess.check_output(['whoami','/user','/fo','csv','/nh'],creationflags=0x08000000)
    sid=list(csv.reader(io.StringIO(who.decode(errors='replace'))))[0][-1]
    if not re.fullmatch(r'S-[0-9-]+',sid):raise ValueError('Не удалось определить ACL пользователя.')
    # Replace the whole DACL, including any previous explicit ACEs.
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    convert=advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[ctypes.c_wchar_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
    convert.restype=ctypes.c_int
    secure=advapi.SetFileSecurityW
    secure.argtypes=[ctypes.c_wchar_p,ctypes.c_uint,ctypes.c_void_p];secure.restype=ctypes.c_int
    descriptor=ctypes.c_void_p()
    if not convert('D:P(A;OICI;FA;;;'+sid+')',1,ctypes.byref(descriptor),None):
        raise ValueError('Не удалось подготовить защищённый ACL.')
    try:
        if not secure(str(directory),0x80000004,descriptor):
            raise ValueError('Не удалось установить защищённый ACL.')
    finally:
        free=ctypes.WinDLL('kernel32').LocalFree
        free.argtypes=[ctypes.c_void_p];free.restype=ctypes.c_void_p;free(descriptor)
    fd,name=tempfile.mkstemp(dir=directory,prefix='intake-',suffix='.new')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            json.dump({'token':token,'admin_ids':[int(admin)]},out);out.flush();os.fsync(out.fileno())
        target=directory/'credentials.json'
        if target.is_symlink():raise ValueError('Файл передачи не должен быть ссылкой.')
        os.replace(name,target)
    finally:
        if Path(name).exists():Path(name).unlink()

def main():
    window=tk.Tk();window.title('TASK 10 — безопасная передача данных');window.resizable(False,False)
    tk.Label(window,text='Только токен BotFather и числовой user ID администратора.\nДанные сохраняются локально вне Git; не отправляйте их в чат.',padx=20,pady=16).pack()
    tk.Label(window,text='Bot token (ввод скрыт)').pack()
    token=tk.Entry(window,width=70,show='*');token.pack(padx=20,pady=5)
    tk.Label(window,text='Telegram user ID администратора').pack()
    admin=tk.Entry(window,width=35);admin.pack(pady=5)
    def submit():
        try:save(token.get().strip(),admin.get().strip())
        except ValueError as e:messagebox.showerror('Проверьте данные',str(e));return
        except Exception:messagebox.showerror('Ошибка','Не удалось сохранить защищённый файл; данные не выводились.');return
        token.delete(0,tk.END);admin.delete(0,tk.END)
        messagebox.showinfo('Сохранено','Защищённый файл готов к передаче Codex. Сообщите в чате только «готово».')
        window.destroy()
    tk.Button(window,text='Сохранить защищённый файл',command=submit,padx=12,pady=8).pack(pady=18)
    token.focus_set();window.mainloop()
if __name__=='__main__':main()
