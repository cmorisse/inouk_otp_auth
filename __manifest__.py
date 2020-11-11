# Copyright 2020 VentorTech OU
# License LGPL-3.0 or later (https://www.gnu.org/licenses/lgpl-3.0).

{
    "name": "inouk_otp_auth",
    "summary": """
        Add 2FA via OTP. 
        Logging into the system requires additional key generated on your mobile device.
        This is a Fork of Ventor Tech 'two_factor_otp_auth' addon.
        """,
    "author": "VentorTech, Cyril MORISSE",
    "category": "Uncategorized",
    "license": "LGPL-3",
    "version": "13.0.1.0.0",
    "images": [
    ],
    "installable": True,
    "depends": [
        "web",
    ],
    "data": [
        "security/res_groups.xml",
        "data/ir_actions_server_data.xml",
        "views/res_users_view.xml",
        "templates/assets.xml",
        "templates/verify_code_template.xml",
        "templates/scan_code_template.xml",
    ],
    "external_dependencies": {
        "python": [
            "qrcode",
            "pyotp",
        ],
    },
}
