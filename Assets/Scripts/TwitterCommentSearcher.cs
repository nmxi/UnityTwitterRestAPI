using System;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.Security.Cryptography;
using System.Net;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

/// <summary>
/// Twitte上で#を用いてつぶやかれたコメントを取得し，
/// CommentQueueに追加していく．
/// </summary>
public class TwitterCommentSearcher : MonoBehaviour {

    [SerializeField] private string _apiKey;
    [SerializeField] private string _apiSecret;
    [SerializeField] private string _accessToken;
    [SerializeField] private string _accessTokenSecret;

    [SerializeField] private int _count;    //一度に取得するtweeet数
    [SerializeField] private string _searchWord;    //検索文字列

    private string _requestURL = "https://api.twitter.com/1.1/search/tweets.json";
    private string _requestMethod = "GET";

    private Dictionary<string, string> _dic;

    private string _oauthSignature; //baase64でエンコードされたsignature

    private WWW www;

    private long _lastFetchTweetID; //最後に取得したTweetのID

    void Awake() {
        //検索ワードに#Unityを代入
        _searchWord = "#Unity";

        //Encode searchWord
        _searchWord = LargeCharUrlEncode(_searchWord);
    }

    public void TwitterSearch() {
        StartCoroutine(Fetch());
    }

    private IEnumerator Fetch() {
        //Fetch UnixTime
        var baseDt = new DateTimeOffset(new DateTime(1970, 1, 1, 0, 0, 0), TimeSpan.Zero);
        long unixTime = (DateTimeOffset.Now - baseDt).Ticks / 10000000;

        //Encode Signature_key
        string signatureKey = _apiSecret + "&" + _accessTokenSecret;

        //for Nonce
        string nonce = unixTime.ToString() + "N";

        //必要なパラメータを列挙
        var _dicTmp = new SortedDictionary<string, string>() {
        {"oauth_nonce", nonce},
        {"oauth_signature_method", "HMAC-SHA1" },
        {"oauth_timestamp", unixTime.ToString()},
        {"oauth_consumer_key", _apiKey},
        {"oauth_token", _accessToken},
        {"oauth_version", "1.0"},
        {"count", _count.ToString()},
        {"q" , _searchWord}    //クエリ
        };

        //ソートを行い_dicに詰めいていく
        _dic = new Dictionary<string, string>();
        foreach (KeyValuePair<string, string> pair in _dicTmp) {
            _dic.Add(pair.Key, pair.Value);
        }

        //_dicをキー=値&キー=値&の順に組み立てる
        string paramStr = "";
        foreach (KeyValuePair<string, string> pair in _dic) {
            paramStr += "&" + pair.Key + "=" + pair.Value;
        }
        paramStr = paramStr.Remove(0, 1);

        //Debug.Log(paramStr);

        //paramStrをURLエンコード
        string encodedRequestParams = LargeCharUrlEncode(paramStr);
        //Debug.Log(encodedRequestParams);

        //リクエストメソッドをエンコード
        string encodedRequestMethod = LargeCharUrlEncode(_requestMethod);

        //リクエストURLをエンコード
        string encodedRequestURL = LargeCharUrlEncode(_requestURL);

        string signatureData = encodedRequestMethod + "&" + encodedRequestURL + "&" + encodedRequestParams;

        //Debug.Log(signatureData);

        //HMAC-SHA1方式のハッシュ値に変換
        _oauthSignature = HashingHMACSHA1(signatureKey, signatureData);

        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(OnRemoteCertificateValidationCallback);

        string url = "https://api.twitter.com/1.1/search/tweets.json?count=" + _count.ToString() + "&q=" + _searchWord;
        //Debug.Log(url);
        HttpWebRequest hwr = (HttpWebRequest)WebRequest.Create(url);

        string authorizationHeaderParams = "Oauth oauth_consumer_key=" + _dic["oauth_consumer_key"] + "," +
                                            "oauth_nonce=" + _dic["oauth_nonce"] + "," +
                                            "oauth_signature=" + WWW.EscapeURL(_oauthSignature) + "," +
                                            "oauth_signature_method=HMAC-SHA1," +
                                            "oauth_timestamp=" + _dic["oauth_timestamp"] + "," +
                                            "oauth_token=" + _dic["oauth_token"] + "," +
                                            "oauth_version=1.0";

        //Debug.Log(authorizationHeaderParams);

        hwr.Headers.Add("Authorization", authorizationHeaderParams);

        hwr.Method = "GET";

        HttpWebResponse res = (HttpWebResponse)hwr.GetResponse();   //fetch

        Stream receiveStream = res.GetResponseStream();

        StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8);

        Encoding ascii = Encoding.ASCII;
        string responseJsonStr = readStream.ReadToEnd();

        Debug.Log(responseJsonStr);

        res.Close();
        readStream.Close();

        yield break;
    }

    public string HashingHMACSHA1(string key, string dataToSign) {
        Byte[] secretBytes = UTF8Encoding.UTF8.GetBytes(key);
        HMACSHA1 hmac = new HMACSHA1(secretBytes);

        Byte[] dataBytes = UTF8Encoding.UTF8.GetBytes(dataToSign);
        Byte[] calcHash = hmac.ComputeHash(dataBytes);
        String calcHashString = Convert.ToBase64String(calcHash);
        return calcHashString;
    }

    //信頼できないSSL証明書を「問題なし」にする
    private bool OnRemoteCertificateValidationCallback(
      System.Object sender,
      X509Certificate certificate,
      X509Chain chain,
      SslPolicyErrors sslPolicyErrors) {
        return true;
    }

    /// <summary>
    /// URLエンコードを大文字で返す
    /// </summary>
    /// <param name="inputText"></param>
    /// <returns></returns>
    private string LargeCharUrlEncode(string inputText) {
        var escapedStr = WWW.EscapeURL(inputText);

        string sdTmp = "";
        for (int i = 0; i < escapedStr.Length; i++) {
            var c = escapedStr[i];
            if (c == '%') {
                sdTmp += c;
                c = escapedStr[i + 1];
                c = c.ToString().ToUpper()[0];
                sdTmp += c;
                c = escapedStr[i + 2];
                c = c.ToString().ToUpper()[0];
                sdTmp += c;
                i = i + 2;
            } else {
                sdTmp += c;
            }
        }

        return sdTmp;
    }
}