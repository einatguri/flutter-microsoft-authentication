package za.co.britehouse.flutter_microsoft_authentication

import android.app.Activity
import android.content.Context
import android.util.Log
import com.microsoft.identity.client.*
import com.microsoft.identity.client.exception.MsalClientException
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalServiceException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import java.io.File
import java.io.FileOutputStream
import java.io.IOException


class FlutterMicrosoftAuthenticationPlugin: MethodCallHandler {
  private var mMultipleAccountApp: IMultipleAccountPublicClientApplication? = null
  private var accountList: List<IAccount>? = null

  companion object {

    lateinit var mainActivity: Activity
    lateinit var mRegistrar: Registrar
    private const val TAG = "FMAuthPlugin"

    @JvmStatic
    fun registerWith(registrar: Registrar) {
      val channel = MethodChannel(registrar.messenger(), "flutter_microsoft_authentication")
      channel.setMethodCallHandler(FlutterMicrosoftAuthenticationPlugin())
      mainActivity = registrar.activity()
      mRegistrar = registrar
    }
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
      // "loadAccount" -> loadAccount(id, result)
      "signOut" -> signOut(result)
      "init" -> initPlugin(configPath)
      else -> result.notImplemented()
    }


  }

  @Throws(IOException::class)
  private fun getConfigFile(path: String): File {
    val key: String = mRegistrar.lookupKeyForAsset(path)
    val configFile = File(mainActivity.applicationContext.cacheDir, "config.json")



    try {
      val assetManager = mRegistrar.context().assets

      val inputStream = assetManager.open(key)
      val outputStream = FileOutputStream(configFile)
      try {
        Log.d(TAG, "File exists: ${configFile.exists()}")
        if (configFile.exists()) {
          outputStream.write("".toByteArray())
        }
        inputStream.copyTo(outputStream)
      } finally {
        inputStream.close()
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
    val context: Context = mainActivity.applicationContext

    PublicClientApplication.createMultipleAccountPublicClientApplication(
            context,
            configFile,
            object : IPublicClientApplication.IMultipleAccountApplicationCreatedListener{
              override fun onCreated(application: IMultipleAccountPublicClientApplication) {
    
                Log.d(TAG, "INITIALIZED")
                mMultipleAccountApp = application
              }

              override fun onError(exception: MsalException) {
                Log.e(TAG, exception.message)
              }
            })
  }

  private fun acquireTokenInteractively(scopes: Array<String>, result: Result) {
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    }

    return mMultipleAccountApp!!.acquireToken(mainActivity, scopes, getAuthInteractiveCallback(result))
  }

  private fun acquireTokenSilently(scopes: Array<String>, authority: String, result: Result) {
    if (mMultipleAccountApp == null) {
      result.error("MsalClientException", "Account not initialized", null)
    }
    mMultipleAccountApp!!.getAccounts(object : IPublicClientApplication.LoadAccountsCallback {
      override fun onTaskCompleted(accountResult: List<IAccount>) {
        if (accountResult.isNotEmpty()) {
          accountList = accountResult
          var currentAccount = accountResult!![0]
          return mMultipleAccountApp!!.acquireTokenSilentAsync(scopes, currentAccount, authority, getAuthSilentCallback(result))
        }
        result.error("MsalClientException", "Account not initialized", null)
      }

      override fun onError(exception: MsalException) {
        Log.e(TAG, exception.message)
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
            Log.e(TAG, exception.message)
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

//   private fun loadAccount(id: String, result: Result) {
//     if (mMultipleAccountApp == null) {
//       result.error("MsalClientException", "Account not initialized", null)
//     }

//     mMultipleAccountApp!!.getAccount(id)

//    mMultipleAccountApp!!.getAccount(id, IMultipleAccountPublicClientApplication.GetAccountCallback {
//        override fun onTaskCompleted(accountResult: List<IAccount>) {
//            accountList = accountResult
//            if (accountList != null) {
//              var currentAccount = accountList!![0]
//              result.success(currentAccount.id)
//            }
//            result.error("MsalClientException", "Account list is null", null)
//          }

//        override fun onError(exception: MsalException) {
//          Log.e(TAG, exception.message)
//                    result.error("MsalException", exception.message, null)
//        }
//    })
// }


}
