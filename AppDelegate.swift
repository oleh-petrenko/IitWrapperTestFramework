import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    var context: EUContext? = nil {
        didSet {
            print(context)
        }
    }
    var pkContext: EUPrivateKeyContext? = nil {
        didSet {
            print(pkContext)
        }
    }
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        return true
    }
}
