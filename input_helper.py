#用于键盘中文字符输入模拟
from pynput.keyboard import Controller
import time
import tkinter as tk

def on_button_click():
        text = entry.get('1.0','end')
        type_chinese_text(text)



def type_chinese_text(text):
    keyboard = Controller()
    time.sleep(3)
    for char in text:
        keyboard.type(char)


def on_button_click1():
        text = entry.get('1.0','end')
        type_chinese_text(text)



def type_chinese_text1(text):
    keyboard = Controller()
    time.sleep(3)
    for char in text:
        keyboard.type(char)
        time.sleep(0.1)  # Adjust the delay between keystrokes if needed


root = tk.Tk()
root.title("暴力粘贴工具")

frame = tk.Frame(root)
frame.pack(pady=20)

label = tk.Label(frame, text="请输入要粘贴的中文文本:\n请注意，请在英文输入法下点击开始。")
label.pack(pady=10)

entry = tk.Text(frame, width=50, height=10)
entry.pack(pady=10)

button = tk.Button(frame, text="点击按钮3秒后开始粘贴", command=on_button_click)
button.pack(pady=10)
judgebutton = tk.Button(frame, text="如果粘贴出现问题，请点击此按钮开始3秒后粘贴", command=on_button_click1)
judgebutton.pack(pady=10)

root.mainloop()

