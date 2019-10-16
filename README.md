### 设置

```javascript
import { AliPay } from 'node-alipay'

const alipay = new AliPay(
  alipayRootCertPath,      // 支付宝根证书文件路径
  alipayCertPublicKeyPath, // 支付宝公钥文件路径
  appId,                   // 应用ID
  appCertPublicKeyPath,    // 应用公钥文件路径
  appPrivateKeyPath,       // 应用私钥文件路径       
  notifyUrl,               // 支付结果回调地址
);
await alipay.init();
```

### 支付参数签名串
```javascript
const payParams = alipay.getPayParams(subject, price, orderId);
```

### 服务端验签
```javascript
const valid = alipay.checkSign(reqParams);
```