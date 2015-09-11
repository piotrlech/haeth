/*
 * Copyright 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.networkconnect;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.util.TypedValue;
import android.view.Menu;
import android.view.MenuItem;

import com.example.android.common.logger.Log;
import com.example.android.common.logger.LogFragment;
import com.example.android.common.logger.LogWrapper;
import com.example.android.common.logger.MessageOnlyLogFilter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Sample application demonstrating how to connect to the network and fetch raw
 * HTML. It uses AsyncTask to do the fetch on a background thread. To establish
 * the network connection, it uses HttpURLConnection.
 *
 * This sample uses the logging framework to display log output in the log
 * fragment (LogFragment).
 */
public class MainActivity extends FragmentActivity {

    public static final String TAG = "Network Connect";
    private static final boolean D = true;

    // Reference to the fragment showing events, so we can clear it with a button
    // as necessary.
    private LogFragment mLogFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.sample_main);

        // Initialize text fragment that displays intro text.
        SimpleTextFragment introFragment = (SimpleTextFragment)
                    getSupportFragmentManager().findFragmentById(R.id.intro_fragment);
        introFragment.setText(R.string.welcome_message);
        introFragment.getTextView().setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16.0f);

        // Initialize the logging framework.
        initializeLogging();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            // When the user clicks FETCH, fetch the first 500 characters of
            // raw HTML from www.google.com.
            case R.id.fetch_action:
                final Charset asciiCs = Charset.forName("US-ASCII");
                String command = "l1f";
                int nonce = 101;
                String HMAC_PASS = "password";
                String HMAC_KEY  = "key";
                //String beforeHmac = "/" + HMAC_PASS + "/" + command + "/" + nonce + "/";
                String beforeHmac = "The quick brown fox jumps over the lazy dog";
                String result = "";
                try {
                    final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
                    final SecretKeySpec secret_key = new javax.crypto.spec.SecretKeySpec(asciiCs.encode(HMAC_KEY).array(), "HmacSHA256");
                    sha256_HMAC.init(secret_key);
                    final byte[] mac_data = sha256_HMAC.doFinal(asciiCs.encode(beforeHmac).array());
                    for (final byte element : mac_data) {
                        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
                    }
                    if(D) Log.e(TAG, "Result:[" + result + "]");
                } catch(Exception e) {
                    if(D) Log.e(TAG, "Crypto Exception");
                }

                //new DownloadTask().execute("http://piotrlech.ddns.net/l1f/42/f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
                //new DownloadTask().execute("http://piotrlech.ddns.net:60371" + result);
                //new DownloadTask().execute("http://m.onet.pl");
                return true;
            // Clear the log view fragment.
            case R.id.clear_action:
              mLogFragment.getLogView().setText("");
              return true;
        }
        return false;
    }

    /**
     * Implementation of AsyncTask, to fetch the data in the background away from
     * the UI thread.
     */
    private class DownloadTask extends AsyncTask<String, Void, String> {

        @Override
        protected String doInBackground(String... urls) {
            try {
                return loadFromNetwork(urls[0]);
            } catch (IOException e) {
              //return getString(R.string.connection_error);
                return e.getMessage();
            }
        }

        /**
         * Uses the logging framework to display the output of the fetch
         * operation in the log fragment.
         */
        @Override
        protected void onPostExecute(String result) {
          Log.i(TAG, result);
        }
    }

    /** Initiates the fetch operation. */
    private String loadFromNetwork(String urlString) throws IOException {
        InputStream stream = null;
        String str ="";

        try {
            stream = downloadUrl(urlString);
            //for(int i = 0; i < 5; i++) {
            //   str = str + readIt(stream, 500);
            //    if(D) Log.e(TAG, "i = " + i + "'" + stream + '+');
            //}
            str = readIt(stream, 500);
       } finally {
           if (stream != null) {
               stream.close();
            }
        }
        return str;
    }

    /**
     * Given a string representation of a URL, sets up a connection and gets
     * an input stream.
     * @param urlString A string representation of a URL.
     * @return An InputStream retrieved from a successful HttpURLConnection.
     * @throws java.io.IOException
     */
    private InputStream downloadUrl(String urlString) throws IOException {
        // BEGIN_INCLUDE(get_inputstream)
        URL url = new URL(urlString);
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("10.144.1.10", 8080));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setReadTimeout(10000 /* milliseconds */);
        conn.setConnectTimeout(15000 /* milliseconds */);
        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        //conn.usingProxy();
        //conn.setAllowUserInteraction(false);
        // Start the query
        conn.connect();
        InputStream stream = conn.getInputStream();
        return stream;
        // END_INCLUDE(get_inputstream)
    }

    /** Reads an InputStream and converts it to a String.
     * @param stream InputStream containing HTML from targeted site.
     * @param len Length of string that this method returns.
     * @return String concatenated according to len parameter.
     * @throws java.io.IOException
     * @throws java.io.UnsupportedEncodingException
     */
    private String readIt(InputStream stream, int len) throws IOException, UnsupportedEncodingException {
        Reader reader = null;
        reader = new InputStreamReader(stream, "UTF-8");
        char[] buffer = new char[len];
        reader.read(buffer);
        return new String(buffer);

        /*BufferedInputStream bis = new BufferedInputStream(stream);
        ByteArrayBuffer baf = new ByteArrayBuffer(50);
        int read = 0;
        int bufSize = 512;
        byte[] bbuffer = new byte[bufSize];
        while(true){
            read = bis.read(bbuffer);
            if(read==-1){
                break;
            }
            baf.append(bbuffer, 0, read);
        }
        return new String(baf.toByteArray());*/
    }

    /** Create a chain of targets that will receive log data */
    public void initializeLogging() {

        // Using Log, front-end to the logging chain, emulates
        // android.util.log method signatures.

        // Wraps Android's native log framework
        LogWrapper logWrapper = new LogWrapper();
        Log.setLogNode(logWrapper);

        // A filter that strips out everything except the message text.
        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        // On screen logging via a fragment with a TextView.
        mLogFragment =
                (LogFragment) getSupportFragmentManager().findFragmentById(R.id.log_fragment);
        msgFilter.setNext(mLogFragment.getLogView());
    }
}
