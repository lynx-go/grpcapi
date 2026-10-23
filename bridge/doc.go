// Package bridge 提供 proto 路由之外的流式 HTTP 协议桥参考实现：
//
//   - sse：Server-Sent Events 下行（事件推送/进度通知）；
//   - upload：HTTP 请求体 → client-streaming 分帧上行（大文件上传）；
//   - ws：WebSocket 双向 JSON 信封（实时通道/执行会话）。
//
// 三个桥都按 extra route 语义挂载（server.ExtraRoute），认证/授权/body limit
// 由 server 的中间件统一执行；EventSource/浏览器 WS 无法带 header 的场景配
// authn.WithQueryTicket 票据凭证。桥只负责协议形态，业务语义（事件来源、
// RPC 目标、信封 schema）由项目经回调注入——这是"参考实现"的边界：采用方
// 不再重写 ~400 行协议帧代码，但不被绑定任何特定业务模型。
package bridge
