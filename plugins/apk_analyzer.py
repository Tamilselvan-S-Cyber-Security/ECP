import logging
from core.base_plugin import BasePlugin

class APKAnalyzer(BasePlugin):
    def __init__(self):
        self.androguard_available = False
        self.apk = None
        self.dvm = None
        self.analysis = None
        self.is_android_raw = None
        self._initialize_androguard()

    def _initialize_androguard(self):
        """Initialize androguard modules with detailed error logging"""
        try:
            logging.info("Attempting to import androguard modules...")

            # First import androguard to check if it's installed
            import androguard
            logging.info(f"Found androguard version: {androguard.__version__}")

            # Import specific modules one by one with error handling
            try:
                from androguard.core.bytecodes import apk
                self.apk = apk
                logging.info("Successfully imported androguard.core.bytecodes.apk")
            except ImportError as e:
                logging.error(f"Failed to import apk module: {str(e)}")
                return

            try:
                from androguard.core.bytecodes import dvm
                self.dvm = dvm
                logging.info("Successfully imported androguard.core.bytecodes.dvm")
            except ImportError as e:
                logging.error(f"Failed to import dvm module: {str(e)}")
                return

            try:
                from androguard.core.analysis import analysis
                self.analysis = analysis
                logging.info("Successfully imported androguard.core.analysis")
            except ImportError as e:
                logging.error(f"Failed to import analysis module: {str(e)}")
                return

            try:
                from androguard.core.androconf import is_android_raw
                self.is_android_raw = is_android_raw
                logging.info("Successfully imported androguard.core.androconf")
            except ImportError as e:
                logging.error(f"Failed to import androconf module: {str(e)}")
                return

            self.androguard_available = True
            logging.info("Successfully loaded all androguard modules")

        except ImportError as e:
            logging.error(f"Failed to import androguard base module: {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error during androguard initialization: {str(e)}")

    @property
    def name(self):
        return "APK Security Analysis"

    def run(self, target: str = None, ports: str = None, apk_data: bytes = None) -> dict:
        """Analyze APK file for security issues"""
        if not self.androguard_available:
            error_msg = "Androguard modules are not properly loaded. Please check installation."
            logging.error(error_msg)
            return {'error': error_msg}

        if not apk_data:
            return {'error': 'No APK data provided'}

        try:
            logging.info("Starting APK analysis")

            # Validate APK format
            if not self.is_android_raw(apk_data):
                return {'error': 'Invalid APK file format'}

            # Parse APK
            a = self.apk.APK(apk_data)
            if not a:
                return {'error': 'Failed to parse APK file'}

            # Create DalvikVMFormat object
            d = self.dvm.DalvikVMFormat(a)
            # Create Analysis object
            dx = self.analysis.Analysis(d)

            # Gather results
            results = {
                'app_name': a.get_app_name(),
                'package': a.get_package(),
                'version': {
                    'name': a.get_androidversion_name(),
                    'code': a.get_androidversion_code()
                },
                'min_sdk': a.get_min_sdk_version(),
                'target_sdk': a.get_target_sdk_version(),
                'permissions': self.analyze_permissions(a),
                'vulnerabilities': self.analyze_vulnerabilities(a, d, dx),
                'libraries': self.analyze_libraries(a)
            }

            results['total_vulnerabilities'] = len(results.get('vulnerabilities', []))
            logging.info("APK analysis completed successfully")
            return results

        except Exception as e:
            error_msg = f"Error analyzing APK: {str(e)}"
            logging.error(error_msg, exc_info=True)
            return {'error': error_msg}

    def analyze_permissions(self, apk_obj):
        """Analyze APK permissions"""
        try:
            dangerous_permissions = [
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.CAMERA',
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS'
            ]

            permissions = apk_obj.get_permissions()
            dangerous = [p for p in permissions if p in dangerous_permissions]

            return {
                'total_permissions': len(permissions),
                'dangerous_permissions': dangerous,
                'all_permissions': list(permissions)
            }
        except Exception as e:
            logging.error(f"Error analyzing permissions: {str(e)}")
            return {'error': str(e)}

    def analyze_vulnerabilities(self, apk_obj, d, dx):
        """Analyze common vulnerabilities"""
        try:
            vulnerabilities = []

            # Check for backup enabled
            if apk_obj.get_element('application', 'android:allowBackup') == 'true':
                vulnerabilities.append({
                    'type': 'Configuration',
                    'name': 'Backup Enabled',
                    'severity': 'Medium',
                    'description': 'Application data can be backed up and restored'
                })

            # Check for debuggable flag
            if apk_obj.get_element('application', 'android:debuggable') == 'true':
                vulnerabilities.append({
                    'type': 'Configuration',
                    'name': 'Debuggable Application',
                    'severity': 'High',
                    'description': 'Application can be debugged in production'
                })

            # Check for exported components
            exported_components = []
            for activity in apk_obj.get_activities():
                if apk_obj.get_element('activity', 'android:exported', activity) == 'true':
                    exported_components.append(activity)

            if exported_components:
                vulnerabilities.append({
                    'type': 'Security',
                    'name': 'Exported Components',
                    'severity': 'Medium',
                    'description': f'Found {len(exported_components)} exported components',
                    'components': exported_components
                })

            return vulnerabilities
        except Exception as e:
            logging.error(f"Error analyzing vulnerabilities: {str(e)}")
            return []

    def analyze_libraries(self, apk_obj):
        """Analyze native libraries"""
        try:
            libs = apk_obj.get_libraries()
            return {
                'total_libraries': len(libs),
                'libraries': list(libs)
            }
        except Exception as e:
            logging.error(f"Error analyzing libraries: {str(e)}")
            return {'total_libraries': 0, 'libraries': []}