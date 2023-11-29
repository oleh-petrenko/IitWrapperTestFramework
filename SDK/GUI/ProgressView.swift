import UIKit

class ProgressView: UIView {

    enum Theme {
        case light
        case dark
    }

    var theme: Theme
    var container: UIStackView
    var activityIndicator: UIActivityIndicatorView
    var label: UILabel
    var glass: UIView


    private var message: String
    private var isModal: Bool

    init(message: String, theme: theme, isModal: Bool) {
        self.message = message
        self.theme = theme
        self.isModal = isModal

        self.container = UIStackView()
        self.activityIndicator = UIActivityIndicatorView()
        self.label = UILabel()
        self.glass = UIView()

        let fontName = self.label.font.fontName
        let fontSize = self.label.font.pointSize
        if let font = UIFont(name: fontName, size: fontSize) {
            let fontAttributes = [NSFontAttributeName: font]
            let size = (message as NSString).size(attributes: fontAttributes)
            super.init(frame: CGRect(x: 0, y: 0, width: size.width + 50, height: 50))
        } else {
            super.init(frame: CGRect(x: 0, y: 0, width: 200, height: 50))
        }

        NotificationCenter.default.addObserver(self, selector: #selector(onRotate), name: NSNotification.Name.UIDeviceOrientationDidChange, object: nil)

        self.layer.cornerRadius = 3
        if (self.theme == .dark) {
            self.backgroundColor = .darkGray
        } else {
            self.backgroundColor = .lightGray
        }

        if self.theme == .dark {
            self.label.textColor = .white
        }else{
            self.label.textColor = .black
        }
        self.label.text = self.message

        self.container.frame = self.frame
        self.container.spacing = 5
        self.container.layoutMargins = UIEdgeInsets(top: 5, left: 5, bottom: 5, right: 5)
        self.container.isLayoutMarginsRelativeArrangement = true

        if (self.theme == .dark) {
            self.activityIndicator = UIActivityIndicatorView(activityIndicatorStyle: .whiteLarge)
            self.activityIndicator.color = .white
        } else {
            self.activityIndicator = UIActivityIndicatorView(activityIndicatorStyle:.whiteLarge)
            self.activityIndicator.color = .black
        }
        self.activityIndicator.startAnimating()

        if let superview = UIApplication.shared.keyWindow {
            if (self.isModal) {
                self.glass.frame = superview.frame;
                if (self.theme == .dark) {
                    self.glass.backgroundColor = UIColor.black.withAlphaComponent(0.5)
                } else {
                    self.glass.backgroundColor = UIColor.white.withAlphaComponent(0.5)
                }

                superview.addSubview(glass)
            }
        }

        container.addArrangedSubview(self.activityIndicator)
        container.addArrangedSubview(self.label)

        self.addSubview(container)
        if let superview = UIApplication.shared.keyWindow {
            self.center = superview.center
            superview.addSubview(self)
        }

        self.hide()
    }

    required init(coder: NSCoder) {
        self.theme = .dark
        self.Message = "Not set!"
        self.isModal = true
        self.container = UIStackView()
        self.activityIndicator = UIActivityIndicatorView()
        self.label = UILabel()
        self.glass = UIView()
        super.init(coder: coder)!
    }

    func onRotate() {
        if let superview = self.superview {
            self.glass.frame = superview.frame
            self.center = superview.center
            // superview.addSubview(self)
        }
    }

    public func show() {
        self.glass.isHidden = false
        self.isHidden = false
    }

    public func hide() {
        self.glass.isHidden = true
        self.isHidden = true
    }
}