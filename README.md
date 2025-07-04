# 🌟 MediaNoteHub 🌟

![Flask](https://img.shields.io/badge/Flask-Powered-6f42c1?logo=flask) ![License](https://img.shields.io/badge/License-MIT-red) ![Python](https://img.shields.io/badge/Python-3.7%2B-blue)

**GoldenRedNotes** 是一款基于 Flask 的多媒体笔记管理与共享平台，支持用户上传图像📷、视频🎥、文本文件📝，并提供笔记的创建、编辑与删除功能。项目配色以金色✨与红色❤️为主题，界面简洁优雅，适合个人或团队记录与分享。

---

## 🚀 主要功能

- 🔐 **免密码快速登录**：输入用户名即可登录，无需繁琐注册流程  
- 📁 **多类型文件上传**：  
  - 图像：PNG、JPG、JPEG、GIF  
  - 视频：MP4、AVI  
  - 文本文件：TXT、MD  
- 📝 **笔记管理**：  
  - 创建、编辑、删除个人笔记  
  - 自动关联到对应用户  
- 🔍 **用户搜索功能**：  
  - 基于“最长公共子序列算法（LCS）”的用户名模糊匹配  
  - 搜索结果按匹配度排序，快速找到目标用户  
- 👀 **资料访问权限**：  
  - 用户可查看自己所有内容，编辑和删除权限完整  
  - 其他用户仅可浏览他人公开笔记和上传的多媒体文件，确保数据安全  
- 🎨 **主题风格**：  
  - 采用金色作为主色调，突出温暖与高贵  
  - 以红色作为强调色，点缀重要操作和警示信息  
  - 完美结合 Bootstrap 5 现代样式，响应式设计兼容手机和桌面端  

---

## ⚙️ 快速开始

### 环境准备

- Python 3.7及以上版本  
- pip 包管理器  

### 安装依赖

```bash
pip install flask flask_sqlalchemy
```

### 启动程序

```bash
git clone https://github.com/wangyifan349/GoldenRedNotes.git
cd GoldenRedNotes
python app.py
```

### 访问网站

打开浏览器访问：

```
http://127.0.0.1:5000/
```

输入用户名即可登录，管理你的文件和笔记！

---

## 📁 项目目录结构简述

```
GoldenRedNotes/
├── app.py            # Flask 应用单文件，包含后端逻辑和前端模版
├── uploads/          # 自动生成，存放各用户上传的文件
└── README.md         # 项目说明文档
```

---

## 🎨 主题配色说明

| 颜色名称 | 颜色值    | 作用描述                  |
| -------- | --------- | ------------------------- |
| 金色✨   | #bfa243   | 主页导航栏及主要按钮背景色 |
| 红色❤️   | #c9302c   | 警告、删除按钮及交互强调色 |

整体基于 Bootstrap 5 变量修改，提供好看又醒目的界面体验。

---

## 🔍 搜索算法介绍

搜索功能采用了 **最长公共子序列（Longest Common Subsequence, LCS）算法**，能够理解用户名中的相似顺序字符，支持模糊查询，提升搜索精准度和用户体验。

---

## 📜 许可证

本项目采用 [MIT 许可证](LICENSE) 进行开源授权。  
© 2024 Wangyifan349

---

## 🤝 贡献指南

欢迎提出 issue 或发送 Pull Request！  
无论是功能增强、UI 优化还是文档完善，都非常期待你的参与。

---

## 📬 联系方式

- GitHub：[wangyifan349](https://github.com/wangyifan349)  
- 邮箱：wangyifan349@gmail.com

---

⭐ **如果你喜欢本项目，别忘了给个 Star 支持一下，谢谢！** ⭐
