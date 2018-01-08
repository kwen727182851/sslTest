package com.example.vanstone.ssltest;

import android.app.Activity;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;


import com.vanstone.system.sdk.Utils;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.Certificate;

import cn.com.jiewen.Cert;
import cn.com.jiewen.Contactless;
import cn.com.jiewen.PosManager;

public class ExampleActivity extends Activity {
    private static final String CLIENT_KET_PASSWORD = "123456";//私钥密码
    private static final String CLIENT_AGREEMENT = "TLS";//使用协议
    private static final String CLIENT_KEY_MANAGER = "X509";//密钥管理器
    private static final String CLIENT_TRUST_MANAGER = "X509";//
    private static final String CLIENT_KEY_KEYSTORE = "BKS";//密库，这里用的是BouncyCastle密库
    private static final String CLIENT_TRUST_KEYSTORE = "BKS";//
    private static String RSA_FILE = "client_RSA.bks";
    private static String EC_FILE = "client_EC.bks";
    private static final String ENCONDING = "utf-8";//字符集
    private static final String LOG_TAG = "ssltest";
    private SSLSocket Client_sslSocket;
    private static final String TAG = ExampleActivity.class.getSimpleName();
    TextView mainTextView;
    TextView mTvServerName;
    TextView mTvPort;
    EditText mEtServerName;
    EditText mEtPort;
    Button mBtnRSA;
    Button mBtnEC;
    Button mBtnClear;
    ScrollView mainTextScroller;
    String exampleUrl;
    int examplePort;

    private PosManager posManager;
    private Context context;
    private  Cert cert;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        mainTextView = (TextView) findViewById(R.id.mainTextView);
        mTvServerName = (TextView) findViewById(R.id.tv_server);
        mTvPort = (TextView) findViewById(R.id.tv_port);
        mEtServerName = (EditText) findViewById(R.id.et_server);
        mEtPort = (EditText) findViewById(R.id.et_port);
        mBtnRSA = (Button) findViewById(R.id.btn_rsa);
        mBtnEC = (Button) findViewById(R.id.btn_ec);
        mBtnClear = (Button) findViewById(R.id.btn_clear);
        mainTextScroller = (ScrollView) findViewById(R.id.mainTextScroller);

        String path = getApplicationContext().getFilesDir().getAbsolutePath();
        if(!fileIsExists(path+File.separator+RSA_FILE) || !fileIsExists(path+File.separator+EC_FILE))
        {
                this.posManager = PosManager.create();
                Log.d(LOG_TAG,"----PosManager create---\n");
                this.cert = this.posManager.cert(context);
                Log.d(LOG_TAG,"----posManger cert------\n");
                if(fileIsExists("/custom/client_pr_pu_trustca.bks"))
                    generateBKS(8,RSA_FILE);
                if(fileIsExists("/custom/client_pr_pu_trustca_ec.bks"))
                    generateBKS(9,EC_FILE);
        }



        mBtnRSA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                exampleUrl = mEtServerName.getText().toString();
                examplePort =Integer.parseInt(mEtPort.getText().toString());
                doRequest();

            }
        });
        mBtnEC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                exampleUrl = mEtServerName.getText().toString();
                examplePort =Integer.parseInt(mEtPort.getText().toString());
                doRequestEC();

            }
        });
        mBtnClear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mainTextView.setText("");
            }
        });

    }


    @Override
    protected void onResume() {
        super.onResume();
    }

    private void updateOutput(String text) {
        mainTextView.setText(mainTextView.getText() + "\n" + text);
    }

    private void doRequest() {

        try {
            mBtnRSA.setEnabled(false);
            mainTextView.setText("Connecting to " + exampleUrl);
            new AsyncTask() {
                @Override
                protected Object doInBackground(Object... objects) {

                    try {
                        publishProgress(init());
                        String str ="hello server,I am client!";
                        getOut(Client_sslSocket,str);
                        publishProgress(getIn(Client_sslSocket));
                        Client_sslSocket.close();

                    } catch (Throwable ex) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        PrintWriter writer = new PrintWriter(baos);
                        ex.printStackTrace(writer);
                        writer.flush();
                        writer.close();
                        publishProgress(ex.toString() + " : " + baos.toString());
                    }

                    return null;
                }

                @Override
                protected void onProgressUpdate(final Object... values) {
                    StringBuilder buf = new StringBuilder();
                    for (final Object value : values) {
                        buf.append(value.toString());
                    }
                    updateOutput(buf.toString());
                    mBtnRSA.setEnabled(true);
                }

                @Override
                protected void onPostExecute(final Object result) {
                    updateOutput("Done!");
                    this.cancel(true);
                    mBtnRSA.setEnabled(true);
                }
            }.execute();

        } catch (Exception ex) {
            Log.e(TAG, "failed to create timeApi", ex);
            updateOutput(ex.toString());
            mBtnRSA.setEnabled(true);
        }
    }

    private void doRequestEC() {

        try {
            mBtnEC.setEnabled(false);
            mainTextView.setText("Connecting to " + exampleUrl);
            new AsyncTask() {
                @Override
                protected Object doInBackground(Object... objects) {

                    try {
                        publishProgress(initEC());
                        String str ="hello server,I am client!";
                        getOut(Client_sslSocket,str);
                        publishProgress(getIn(Client_sslSocket));
                        Client_sslSocket.close();

                    } catch (Throwable ex) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        PrintWriter writer = new PrintWriter(baos);
                        ex.printStackTrace(writer);
                        writer.flush();
                        writer.close();
                        publishProgress(ex.toString() + " : " + baos.toString());
                    }

                    return null;
                }

                @Override
                protected void onProgressUpdate(final Object... values) {
                    StringBuilder buf = new StringBuilder();
                    for (final Object value : values) {
                        buf.append(value.toString());
                    }
                    updateOutput(buf.toString());
                    mBtnEC.setEnabled(true);
                }

                @Override
                protected void onPostExecute(final Object result) {
                    updateOutput("Done!");
                    this.cancel(true);
                    mBtnEC.setEnabled(true);
                }
            }.execute();

        } catch (Exception ex) {
            Log.e(TAG, "failed to create timeApi", ex);
            updateOutput(ex.toString());
            mBtnEC.setEnabled(true);
        }
    }

    public String init() {
        StringBuffer str = new StringBuffer("");
        String RSA_path = getApplicationContext().getFilesDir().getAbsolutePath();

        try {

            //取得SSL的SSLContext实例
            SSLContext sslContext = SSLContext.getInstance(CLIENT_AGREEMENT);
            //取得KeyManagerFactory和TrustManagerFactory的X509密钥管理器实例
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(CLIENT_KEY_MANAGER);
            //取得BKS密库实例
            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(CLIENT_TRUST_MANAGER);
            KeyStore kks= KeyStore.getInstance(CLIENT_KEY_KEYSTORE);
            KeyStore tks = KeyStore.getInstance(CLIENT_TRUST_KEYSTORE);
            //加客户端载证书和私钥,通过读取资源文件的方式读取密钥和信任证书


            FileInputStream fis = new FileInputStream(RSA_path+File.separator+RSA_FILE);
            kks.load(fis,"123456".toCharArray());
            fis.close();
            FileInputStream fis_tks = new FileInputStream(RSA_path+File.separator+RSA_FILE);
            tks.load(fis_tks,"123456".toCharArray());
            fis_tks.close();
            //kks.load(getAssets().open("client_pr_pu_trustca.bks"),"123456".toCharArray());
            //tks.load(getAssets().open("client_pr_pu_trustca.bks"),"123456".toCharArray());
            //初始化密钥管理器
            keyManager.init(kks,CLIENT_KET_PASSWORD.toCharArray());
            trustManager.init(tks);
            //初始化SSLContext
            sslContext.init(keyManager.getKeyManagers(),trustManager.getTrustManagers(),null);
            //生成SSLSocket
            String [] cipherSuites =new String[1];
            //cipherSuites[0]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";

            SSLSocketFactory factory = sslContext.getSocketFactory();
            Client_sslSocket = (SSLSocket) factory.createSocket(mEtServerName.getText().toString(),examplePort);
            //Log.d(LOG_TAG,"----create socket ok----");
            Client_sslSocket.startHandshake();
            //Client_sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(mEtServerName.getText().toString(), examplePort);
            printServerCertificate(Client_sslSocket);
            printSocketInfo(Client_sslSocket);

            cipherSuites = Client_sslSocket.getSupportedCipherSuites();
            Client_sslSocket.setEnabledCipherSuites(cipherSuites);
            return  str.toString();

        } catch (KeyStoreException e) {
            Log.i(TAG,"Keystore ks error");
        }catch (NoSuchAlgorithmException e) {
            Log.i(TAG,"No such algorithm for ks.load");
            e.printStackTrace();
        }catch (CertificateException e){
            Log.i(TAG,"certificate missing");
            e.printStackTrace();
        }catch (UnrecoverableKeyException e) {
            Log.i(TAG,"unrecoverableKeyException");
            e.printStackTrace();
        } catch (UnknownHostException e) {
            Log.i(TAG,"Unknown host");
            e.printStackTrace();
        } catch (KeyManagementException e) {
            Log.i(TAG,"key management exception");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i(TAG,"No I/O");
            e.printStackTrace();
        }

        str.append("Peer certificate Error!!!\n");
        return str.toString();

    }

    public boolean generateBKS(int param, String srcFile)
    {
        //PosManager posManager;
       // Cert cert;

        String path = getApplicationContext().getFilesDir().getAbsolutePath();
        byte[] data = new byte[5*1024];
        //int param = 8;
        int ret = cert.getClientTrustRootCert(param, data);
            //Log.d(LOG_TAG,"ret:"+ret + "  getCer:"+ Utils.bytesToHexString(data));
        /*先获取有效数据长度*/

        int length = (data[7] & 0xff) | ((data[6] << 8) & 0xff00) | ((data[5] << 24) >>> 8) | (data[4] << 24) ;
        Log.d(LOG_TAG,"----length----"+length);
        if((length <= 0) || (length > ret))
        {
            return false;
        }

        byte[] resultdata = new byte[length];
        System.arraycopy(data,40,resultdata,0,length);
        //Log.d(LOG_TAG,"----copy data---"+Utils.bytesToHexString(resultdata));

        getFile(resultdata, path,srcFile);
        return true;

    }

    public boolean fileIsExists(String strFile)
    {
        try
        {
            File f=new File(strFile);
            if(!f.exists())
            {
                return false;
            }

        }
        catch (Exception e)
        {
            return false;
        }

        return true;
    }
    /**
     * 根据byte数组，生成文件
     */
    public boolean getFile(byte[] bfile,String filePath, String fileName) {
        BufferedOutputStream bos = null;
        FileOutputStream fos = null;
        File file = null;

        try {
            File dir = new File(filePath);
            if(!dir.exists()&&dir.isDirectory()){//判断文件目录是否存在
                //dir.mkdirs();
                return false;
            }
            file = new File(filePath+File.separator+fileName);
            if(!file.exists())
            {
                fos = new FileOutputStream(file);
                bos = new BufferedOutputStream(fos);
                bos.write(bfile);
                Log.d(LOG_TAG,"--create file ok---");
            }
            else
            {
                Log.d(LOG_TAG,"---file exist---");
                if(file.length() == 0)
                {
                    Log.d(LOG_TAG,"---file len=0---");
                    file.delete();
                    return false;
                }
                return true;
            }

        } catch (Exception e) {
            Log.d(LOG_TAG,"----create file error---");
            e.printStackTrace();
            return false;
        } finally {
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
        Log.d(LOG_TAG,"---close buffer and filestream ok---");
        return true;
    }

    public void printServerCertificate(SSLSocket socket) {
        try {
            X509Certificate serverCerts =
                    (X509Certificate) socket.getSession().getPeerCertificates()[0];
            X509Certificate myCert = serverCerts;
            Log.i(TAG,"====Certificate:" + "====");
            Log.i(TAG,"-Public Key-\n" + myCert.getPublicKey());
            Log.i(TAG,"-Certificate Type-\n " + myCert.getType());

            System.out.println();
        } catch (SSLPeerUnverifiedException e) {
            Log.i(TAG,"Could not verify peer");
            e.printStackTrace();
        }
    }
    public void printSocketInfo(SSLSocket s) {
        Log.i(TAG,"Socket class: "+s.getClass());
        Log.i(TAG,"   Remote address = "
                +s.getInetAddress().toString());
        Log.i(TAG,"   Remote port = "+s.getPort());
        Log.i(TAG,"   Local socket address = "
                +s.getLocalSocketAddress().toString());
        Log.i(TAG,"   Local address = "
                +s.getLocalAddress().toString());
        Log.i(TAG,"   Local port = "+s.getLocalPort());
        Log.i(TAG,"   Need client authentication = "
                +s.getNeedClientAuth());
        SSLSession ss = s.getSession();
        Log.i(TAG,"   Cipher suite = "+ss.getCipherSuite());
        Log.i(TAG,"   Protocol = "+ss.getProtocol());
    }

    public String initEC() {
        StringBuffer str = new StringBuffer("");
        String EC_path = getApplicationContext().getFilesDir().getAbsolutePath();
        try {
            //取得SSL的SSLContext实例
            SSLContext sslContext = SSLContext.getInstance(CLIENT_AGREEMENT);
            //取得KeyManagerFactory和TrustManagerFactory的X509密钥管理器实例
            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(CLIENT_KEY_MANAGER);
            //取得BKS密库实例
            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(CLIENT_TRUST_MANAGER);
            KeyStore kks= KeyStore.getInstance(CLIENT_KEY_KEYSTORE);
            KeyStore tks = KeyStore.getInstance(CLIENT_TRUST_KEYSTORE);
            //加客户端载证书和私钥,通过读取资源文件的方式读取密钥和信任证书
            FileInputStream fis = new FileInputStream(EC_path+File.separator+EC_FILE);
            kks.load(fis,"123456".toCharArray());
            fis.close();
            FileInputStream fis_tks = new FileInputStream(EC_path+File.separator+EC_FILE);
            tks.load(fis_tks,"123456".toCharArray());
            fis_tks.close();
            //kks.load(getAssets().open("client_pr_pu_trustca_ec.bks"),"123456".toCharArray());
            //tks.load(getAssets().open("client_pr_pu_trustca_ec.bks"),"123456".toCharArray());
            //初始化密钥管理器
            keyManager.init(kks,CLIENT_KET_PASSWORD.toCharArray());
            trustManager.init(tks);
            //初始化SSLContext
            sslContext.init(keyManager.getKeyManagers(),trustManager.getTrustManagers(),null);
            //生成SSLSocket
            String [] cipherSuites =new String[1];
            //cipherSuites[0]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";

            SSLSocketFactory factory = sslContext.getSocketFactory();
            Client_sslSocket = (SSLSocket) factory.createSocket(mEtServerName.getText().toString(),examplePort);
            Client_sslSocket.startHandshake();

            //Client_sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(mEtServerName.getText().toString(),examplePort);

            cipherSuites = Client_sslSocket.getSupportedCipherSuites();
            //Log.e("log",cipherSuites.toString());
            Client_sslSocket.setEnabledCipherSuites(cipherSuites);

            return  str.toString();
        } catch (KeyStoreException e) {
            Log.i(TAG,"Keystore ks error");
        }catch (NoSuchAlgorithmException e) {
            Log.i(TAG,"No such algorithm for ks.load");
            e.printStackTrace();
        }catch (CertificateException e){
            Log.i(TAG,"certificate missing");
            e.printStackTrace();
        }catch (UnrecoverableKeyException e) {
            Log.i(TAG,"unrecoverableKeyException");
            e.printStackTrace();
        } catch (UnknownHostException e) {
            Log.i(TAG,"Unknown host");
            e.printStackTrace();
        } catch (KeyManagementException e) {
            Log.i(TAG,"key management exception");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i(TAG,"No I/O");
            e.printStackTrace();
        }
        str.append("Peer certificate Error!!!\n");
        return str.toString();
    }

    /**
     * 向server输出信息。
     *
     * @param socket
     *            The client socket
     * @param message
     *            to be delivered to server
     */
    public void getOut(SSLSocket socket, String message) {
        Log.i(LOG_TAG, "come int getOut()");
        OutputStream output = null;

        try {
            // 这样发信息，不会堵塞socket
            output = socket.getOutputStream();
            BufferedOutputStream bufferedOutput = new BufferedOutputStream(
                    output);
            bufferedOutput.write(message.getBytes());
            bufferedOutput.flush();
			/*
			 * PrintStream out; out = new PrintStream( new
			 * BufferedOutputStream(socket.getOutputStream(), 8192), true);
			 * //autoFlush==true //这样发信息，会堵塞socket out.println(message);
			 * out.println();
			 */
            Log.i(LOG_TAG, "send server message is: " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从server读出信息
     *
     * @param socket
     *            The client socket
     */
    public String getIn(SSLSocket socket) {

        BufferedReader in = null;
        StringBuffer str = new StringBuffer("server return message\n");
        char [] readBuf =new char[1024];
        try {
            // 显示授权信息.
            X509Certificate cert = (X509Certificate) socket.getSession()
                    .getPeerCertificates()[0];// getLocalCertificates
            String subject = cert.getSubjectDN().getName();
            String issuer = cert.getIssuerDN().getName();
//            str.append("subject:"+subject+"\n");
//            str.append("issuer:"+issuer);
            in = new BufferedReader(new InputStreamReader(
                    socket.getInputStream()), 8192);
            Log.e(LOG_TAG,"====in.ready()===="+in.ready());//不注释不显示服务端数据：in.ready()=false
            int a = in.read(readBuf);
            str.append(readBuf);
            return str.toString();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        str.append("NULL");
        return str.toString();
    }
}

