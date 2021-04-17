from jinja2 import PackageLoader, Environment
import datetime
import weakpwd_original.weakpwd as wp

env = Environment(loader=PackageLoader('weakpwd_original', 'templates'))
template = env.get_template('report-template.html')


def test():
    print(template.render({'start_time': wp.starttime,
                           'end_time': wp.endtime,
                           'weakpwd_list': wp.report_success,
                           'weakpwd_num': len(wp.report_success),
                           'weakpwd_warning_dict': wp.report_warning,
                           })
          )
