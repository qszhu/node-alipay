import * as crypto from 'crypto';

import * as moment from 'moment';

import { readPublicKey, readPrivateKey, getCertSN, getRootCertSN } from './certUtils';

export class AliPay {
  private appPrivateKey?: crypto.KeyObject;
  private appCertSN?: string;
  private alipayRootSN?: string;
  private alipayPublicKey?: crypto.KeyObject;

  constructor(
    private alipayRootCertPath: string,
    private alipayPublicKeyPath: string,
    private appId: string,
    private appCertPath: string,
    private appPrivateKeyPath: string,
    private notifyUrl?: string,
  ) {}

  async init() {
    this.appPrivateKey = await readPrivateKey(this.appPrivateKeyPath);
    this.appCertSN = getCertSN(this.appCertPath);
    this.alipayRootSN = await getRootCertSN(this.alipayRootCertPath);
    this.alipayPublicKey = await readPublicKey(this.alipayPublicKeyPath);
  }

  private getParamStr(params: { [key: string]: string }) {
    return Object.keys(params)
      .sort()
      .map(key => `${key}=${params[key]}`)
      .join('&');
  }

  checkSign(params: { [key: string]: string }) {
    const { sign } = params;
    delete params['sign'];
    delete params['sign_type'];
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(this.getParamStr(params));
    return verify.verify(this.alipayPublicKey!, Buffer.from(sign, 'base64'));
  }

  private signParams(params: { [key: string]: string }) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(this.getParamStr(params));
    return sign.sign(this.appPrivateKey!, 'base64');
  }

  private getRequestParams(method: string, bizContent: object) {
    const params: { [key: string]: string } = {
      method,
      app_id: this.appId,
      charset: 'utf-8',
      sign_type: 'RSA2',
      version: '1.0',
      biz_content: JSON.stringify(bizContent),
      timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
      notify_url: this.notifyUrl!,
      app_cert_sn: this.appCertSN!,
      alipay_root_cert_sn: this.alipayRootSN!,
    };
    params.sign = this.signParams(params);
    Object.keys(params).forEach(key => (params[key] = encodeURIComponent(params[key])));
    const query = Object.keys(params)
      .map(key => `${key}=${params[key]}`)
      .join('&');
    return query;
  }

  getPayParams(subject: string, price: number, orderId: string) {
    const params = {
      subject,
      total_amount: (price / 100).toFixed(2),
      out_trade_no: orderId,
      // product_code: 'QUICK_MSECURITY_PAY'
    };
    return this.getRequestParams('alipay.trade.app.pay', params);
  }
}
