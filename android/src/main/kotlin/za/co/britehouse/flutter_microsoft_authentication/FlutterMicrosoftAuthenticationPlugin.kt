package za.co.britehouse.flutter_microsoft_authentication

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.annotation.NonNull
import com.microsoft.identity.client.*
import com.microsoft.identity.client.exception.MsalClientException
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalServiceException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import io.flutter.FlutterInjector
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File
import java.io.FileOutputStream
import java.io.IOException


class FlutterMicrosoftAuthenticationPlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  private var mMultipleAccountApp: IMultipleAccountPublicClientApplication? = null
  private var accountList: List<IAccount>? = null

  companion object {

    lateinit var context: Context
    private var activity: Activity? = null
    private var binaryMessenger: BinaryMessenger? = null
    private var channel: MethodChannel? = null
    private val TAG = "FMAuthPlugin"
  }



    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
      binaryMessenger = flutterPluginBinding.binaryMessenger
      context = flutterPluginBinding.applicationContext
      Log.d("DART/NATIVE", "context is $context")


    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
      channel?.setMethodCallHandler(null)
      //release resources
    }

    override fun onDetachedFromActivity() {
      Log.d("DART/NATIVE", "onDetachedFromActivity")
      activity = null
  }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    Log.d("DART/NATIVE", "onReattachedToActivityForConfigChanges")
    onAttachedToActivity(binding)
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    Log.d("DART/NATIVE", "onAttachedToActivity")
    activity = binding.activity;

    Log.d("DART/NATIVE", "activity is $activity")


    channel = binaryMessenger?.let { MethodChannel(it, "flutter_microsoft_authentication") }
    channel?.setMethodCallHandler(FlutterMicrosoftAuthenticationPlugin());
  }

  override fun onDetachedFromActivityForConfigChanges() {
    Log.d("DART/NATIVE", "detach from activity for config changes")
    activity = null

  }

  override fun onMethodCall(call: MethodCall, result: Result) {

    val scopesArg : ArrayList<String>? = call.argument("kScopes")
    val scopes: Array<String>? = scopesArg?.toTypedArray()
    val authority: String? = call.argument("kAuthority")
    val configPath: String? = call.argument("configPath")


    if (configPath == null) {
      Log.d(TAG, "no config")
      result.error("NO_CONFIG","Call must include a config file path", null)
      return
    }

    if(scopes == null){
      Log.d(TAG, "no scope")
      result.error("NO_SCOPE","Call must include a scope", null)
      return
    }

    if(authority == null){
      Log.d(TAG,"error no authority")
      result.error("NO_AUTHORITY", "Call must include an authority", null)
      return
    }

    when(call.method){
      "acquireTokenInteractively" -> acquireTokenInteractively(scopes, result)
      "acquireTokenSilently" -> acquireTokenSilently(scopes, authority, result)
      "getUsername" -> getUsername(result)
      "signOut" -> signOut(result)
      "init" -> initPlugin(configPath)
      else -> result.notImplemented()
    }


  }

  @Throws(IOException::class)
  private fun getConfigFile(path: String): File {
    val key: String =  FlutterInjector.instance().flutterLoader().getLookupKeyForAsset(path)
    val configFile = File(activity?.applicationContext?.cacheDir, "config.json")



    try {
      val assetManager =  activity?.applicationContext?.assets

      val inputStream = assetManager?.open(key)
      val outputStream = FileOutputStream(configFile)
      try {
        Log.d(TAG, "File exists: ${configFile.exists()}")
        if (configFile.exists()) {
          outputStream.write("".toByteArray())
        }
        inputStream?.copyTo(outputStream)
      } finally {
        inputStream?.close()
        outputStream.close()
      }
      return  configFile

    } catch (e: IOException) {
      throw IOException("Could not open config file", e)
    }
  }

  private fun initPlugin(assetPath: String) {
    createMultipleAccountPublicClientApplication(assetPath)
  }

  private fun createMultipleAccountPublicClientApplication(assetPath: String) {
    val configFile = getConfigFile(assetPath)
    val context: Context? = activity?.applicationContext

    if (context != null)
    PublicClientApplication.createMultipleAccountPublicClientApplication(
            context,
            configFile,
            object : IPublicClientApplication.IMultipleAccountApplicationCreatedListener{
              override fun onCreated(application: IMultipleAccountPublicClientApplication) {
    
                Log.d(TAG, "INITIALIZED")
                mMultipleAccountApp = application
              }

              override fun onError(exception: MsalException) {
                //Log.e(TAG, exception.message)
              }
            })
  }

  private fun acquireTokenInteractively(scopes: Array<String>, result: Result) {
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    } else if (activity == null) {
      Log.d(TAG, "Activity is null")
      result.error("MsalClientException", "Activity is null", null)
    }
    return mMultipleAccountApp!!.acquireToken(activity!!, scopes, getAuthInteractiveCallback(result))
  }

  private fun acquireTokenSilently(scopes: Array<String>, authority: String, result: Result) {
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    }
    mMultipleAccountApp!!.getAccounts(object : IPublicClientApplication.LoadAccountsCallback {
      override fun onTaskCompleted(accountResult: List<IAccount>) {
        if (accountResult.isNotEmpty()) {
          accountList = accountResult
          var currentAccount = accountResult[0]
          return mMultipleAccountApp!!.acquireTokenSilentAsync(scopes, currentAccount, authority, getAuthSilentCallback(result))
        }
        result.error("MsalClientException", "Account not initialized", null)
      }

      override fun onError(exception: MsalException) {
       // Log.e(TAG, exception.message)
        result.error("MsalClientException", "Account not initialized", null)
      }
    })


  }

  private fun signOut(result: Result){
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    }

    mMultipleAccountApp!!.removeAccount(
      accountList!![0],
      object : IMultipleAccountPublicClientApplication.RemoveAccountCallback {
          override fun onRemoved() {
            result.success("ACCOUNT REMOVED")

          }
  
          override fun onError(exception: MsalException) {
     //       Log.e(TAG, exception.message)
            result.error("ERROR", exception.errorCode, null)
          }
      })

  }

  private fun getAuthInteractiveCallback(result: Result): AuthenticationCallback {

    return object : AuthenticationCallback {

      override fun onSuccess(authenticationResult: IAuthenticationResult) {
        /* Successfully got a token, use it to call a protected resource - MSGraph */
        Log.d(TAG, "Successfully authenticated")
        Log.d(TAG, "ID Token: " + authenticationResult.account.claims!!["id_token"])
        val accessToken = authenticationResult.accessToken
        result.success(accessToken)
      }

      override fun onError(exception: MsalException) {
        /* Failed to acquireToken */

        Log.d(TAG, "Authentication failed: ${exception.errorCode}")

        if (exception is MsalClientException) {
          /* Exception inside MSAL, more info inside MsalError.java */
          Log.d(TAG, "Authentication failed: MsalClientException")
          result.error("MsalClientException",exception.errorCode, null)

        } else if (exception is MsalServiceException) {
          /* Exception when communicating with the STS, likely config issue */
          Log.d(TAG, "Authentication failed: MsalServiceException")
          result.error("MsalServiceException",exception.errorCode, null)
        }
      }

      override fun onCancel() {
        /* User canceled the authentication */
        Log.d(TAG, "User cancelled login.")
        result.error("MsalUserCancel", "User cancelled login.", null)
      }
    }
  }

  private fun getAuthSilentCallback(result: Result): AuthenticationCallback {
    return object : AuthenticationCallback {

      override fun onSuccess(authenticationResult: IAuthenticationResult) {
        Log.d(TAG, "Successfully authenticated")
        val accessToken = authenticationResult.accessToken
        result.success(accessToken)
      }

      override fun onError(exception: MsalException) {
        /* Failed to acquireToken */
        Log.d(TAG, "Authentication failed: ${exception.message}")

        when (exception) {
            is MsalClientException -> {
              /* Exception inside MSAL, more info inside MsalError.java */
              result.error("MsalClientException",exception.message, null)
            }
          is MsalServiceException -> {
            /* Exception when communicating with the STS, likely config issue */
            result.error("MsalServiceException",exception.message, null)
          }
          is MsalUiRequiredException -> {
            /* Tokens expired or no session, retry with interactive */
            result.error("MsalUiRequiredException",exception.message, null)
          }
        }
      }

      override fun onCancel() {
        /* User cancelled the authentication */
        Log.d(TAG, "User cancelled login.")
        result.error("MsalUserCancel", "User cancelled login.", null)
      }
    }
  }

  private fun getUsername( result: Result) {
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    }

    mMultipleAccountApp!!.getAccounts(object : IPublicClientApplication.LoadAccountsCallback {
      override fun onTaskCompleted(accountResult: List<IAccount>) {
        if (accountResult.isNotEmpty()) {
          accountList = accountResult
          var currentAccount = accountResult[0]
          var username = currentAccount.username
          return result.success(username)
        }
        result.error("MsalClientException", "Account not initialized", null)
      }

      override fun onError(exception: MsalException) {
       // Log.e(TAG, exception.message)
        result.error("MsalClientException", "Account not initialized", null)
      }
    })


  }

}
