# WeChat Input Border Customizer

一个适用于 **越狱 iOS 设备** 的插件（Tweak），支持自定义 **微信输入框的边框粗细和颜色**。本插件通过注入方式对微信界面进行调整，提供了简单的设置界面，可自由配置边框效果。

---

## ✨ 功能特性

- 支持设置微信输入框的：
  - ✅ 边框颜色（支持十六进制、预设颜色）
  - ✅ 边框粗细（线宽自定义）
- 实时生效，无需重启微信
- 提供偏好设置界面，集成至系统「设置」App

---

## 📱 支持环境

| 项目         | 说明                         |
|--------------|------------------------------|
| 支持应用     | 微信（WeChat）               |
| 兼容版本     | 微信 v8.0.30 ~ v8.0.xx（待补充） |
| 系统要求     | iOS 14 ~ iOS 16（越狱设备）   |
| 插件类型     | Tweak（Theos 编译）          |
| 设置支持     | ✅ 通过 PreferenceLoader 展示 |

---

## 🧩 安装方式

### 方法一：通过越狱源安装（推荐）
> _暂未提供正式源，敬请期待。_

### 方法二：本地打包安装

1. 安装依赖（确保已安装 Theos 环境）：
    ```sh
    git clone https://github.com/your/repo.git
    cd repo
    make package
    ```

2. 使用 `Filza` 或 `scp` 将 `.deb` 文件安装到设备：
    ```sh
    dpkg -i com.example.wechatborder.deb
    ```

3. 重启微信（或 Respring）

---

## ⚙️ 设置说明

设置路径：**设置 > WeChatBorderCustomizer**

- **边框颜色**：支持输入 HEX（如 `#FF0000`）、RGB 或从预设中选择
- **边框粗细**：滑动选择 1.0 ~ 5.0 像素
- **恢复默认**：点击按钮恢复微信默认样式

---

## 🛠️ 开发者信息

- **作者**：[@yourname](https://github.com/yourname)
- **项目地址**：[GitHub Repo](https://github.com/your/repo)
- **技术栈**：Logos / Theos / Objective-C / PreferenceLoader

---

## 📸 效果演示（可选）

> 请在此处插入使用前后对比截图或动图

---

## 📜 License

本项目仅用于学习与研究目的，禁止用于商业用途或侵犯他人权益。

