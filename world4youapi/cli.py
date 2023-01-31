import getpass
import sys
import argparse
import logging

from .api import MyWorld4You

logging.basicConfig(level=logging.INFO, filename='w4y.log')
log = logging.getLogger(__name__)

outhandler = logging.StreamHandler()

log.addHandler(outhandler)


class MyWorld4YouCli:

    def __init__(self, api: MyWorld4You = None) -> None:
        self._api = api or MyWorld4You()

    def login(self, *args, **kwargs):
        return self._api.login(*args, **kwargs)

    def add(self, record_name: str = None, record_type: str = None, record_value: str = None, *cmd_args):
        if not record_name or not record_type or not record_value or len(cmd_args) != 0:
            log.error('usage: world4you add <fqdn> <dns-type> <value>')
            return False
        return self._api.add_resource_record(record_type, record_name, record_value)

    def update(self,
               record_name: str = None,
               record_type: str = None,
               record_value_old: str = None,
               record_value_new: str = None,
               *cmd_args):
        if record_value_new is None:
            if record_value_old is None:
                record_value_new = record_type
                record_type = None
            else:
                record_value_new = record_value_old
                record_value_old = None
        if not record_name or not record_value_new or len(cmd_args) != 0:
            log.error('usage: word4you update <fqdn> [<dns-type> [<old-value>]] <new-value>')
            return False
        try:
            rr = self._api.get_resource_record(fqdn=record_name, rr_type=record_type, value=record_value_old)
        except KeyError:
            log.error('unable to find resource record')
            return False
        return self._api.update_resource_record(rr, new_value=record_value_new)

    def alter(self,
              record_name: str = None,
              record_type_old: str = None,
              record_value_old: str = None,
              record_type_new: str = None,
              record_value_new: str = None,
              *cmd_args):
        if not record_name or not record_type_old or not record_value_old or record_type_new or len(cmd_args) != 0:
            log.error('usage: world4you alter <fqdn> <old-dns-type> <old-value> <new-dns-type> [<new-value>]')
            return False
        try:
            rr = self._api.get_resource_record(record_name, record_type_old, record_value_old)
        except KeyError:
            log.error('unable to find resource record')
            return False
        return self._api.update_resource_record(rr, new_type=record_type_new, new_value=record_value_new)

    def delete(self, record_name: str = None, record_type: str = None, record_value: str = None, *cmd_args):
        if not record_name or len(cmd_args) != 0:
            log.error('usage: world4you delete <fqdn> [<dns-type> [<value>]]')
            return False
        try:
            rr = self._api.get_resource_record(record_name, record_type, record_value)
        except KeyError:
            log.error('unable to find resource record')
            return False
        return self._api.delete_resource_record(rr)

    def table(self, *cmd_args):
        if not (len(cmd_args) == 0 or (len(cmd_args) == 1 and cmd_args[0] == 'full')):
            log.error('usage: world4you table [full]')
            return False

        len_fqdn, len_value = 0, 0
        for p in self._api.packages:
            for rr in p.resource_records:
                if len(rr.fqdn) > len_fqdn:
                    len_fqdn = len(rr.fqdn)
                if len(rr.value) > len_value:
                    len_value = len(rr.value)

        len_val_col = min(len_value, 72)
        if 'full' not in cmd_args:
            len_value = len_val_col

        log.info(f'┏━{"":━<{len_fqdn}s}━┯━{"":━<8s}━┯━{"":━<{len_val_col}s}━┓')
        log.info(f'┃ {"Name":^{len_fqdn}s} │ {"Type":^8s} │ {"Value":^{len_val_col}s} ┃')
        log.info(f'┣━{"":━<{len_fqdn}s}━┿━{"":━<8s}━┿━{"":━<{len_val_col}s}━┫')

        first = True
        for p in self._api.packages:
            for rr in p.resource_records:
                if not first:
                    log.info(f'┠─{"":─<{len_fqdn}s}─┼─{"":─<8s}─┼─{"":─<{len_val_col}s}─┨')
                values = [rr.value[start:start + len_value] for start in range(0, len(rr.value), len_value)]
                align = '>' if len(values) == 1 else '<'
                log.info(f'┃ {rr.fqdn:>{len_fqdn}s} │ {rr.type:^8s} │ {values[0]:{align}{len_val_col}s} ┃')
                for v in values[1:]:
                    log.info(f'┃ {"":<{len_fqdn}s} │ {"":<8s} │ {v:{align}{len_val_col}s} ┃')
                first = False

        log.info(f'┗━{"":━<{len_fqdn}s}━┷━{"":━<8s}━┷━{"":━<{len_val_col}s}━┛')
        return True

    def csv(self, *cmd_args):
        if len(cmd_args) != 0:
            log.error('usage: world4you csv')
            return False
        for p in self._api.packages:
            for rr in p.resource_records:
                log.info(f'{rr.fqdn:s},{rr.type:s},\"{rr.value:s}\"')
        return True

    def reload(self, *cmd_args):
        if len(cmd_args) != 0:
            log.error("usage: world4you reload")
            return False

        log.info('Retrieving DNS entries...')
        self._api.load_packages()
        log.info('Successfully retrieved DNS entries')
        return True

    @staticmethod
    def usage(*cmd_args):
        if len(cmd_args) != 0:
            log.error("usage: help")
        else:
            log.info("Commands: ")
            log.info("  help")
            log.info("  list / table [full]")
            log.info("  reload")
            log.info("  exit / quit")
            log.info("  add <fqdn> <dns-type> <value>")
            log.info("  update <fqdn> [<dns-type> [<old-value>]] <new-value>")
            log.info("  alter <fqdn> <old-dns-type> <old-value> <new-dns-type> [<new-value>]")
            log.info("  delete <fqdn> [<dns-type> [<value>]]")

    @staticmethod
    def quit(*cmd_args):
        if len(cmd_args) != 0:
            log.error("usage: world4you quit")
            return False
        log.info("Goodbye!")
        sys.exit(0)

    def interactive(self):

        def unalias(cmd):
            aliases = {'list': 'table', 'exit': 'quit', 'help': 'usage'}
            return aliases.get(cmd, cmd)

        while True:
            line = input('> ')
            cmd, *args = line.split(' ')
            ucmd = unalias(cmd)
            try:
                getattr(self, ucmd)(*args)
            except AttributeError:
                log.error("unknown action. Type 'help' for help")
            except ConnectionError as e:
                log.error(str(e))
            except IndexError:
                log.error("unable to find resource record")
            except (KeyError, RuntimeError) as e:
                log.error(str(e))


def parse_args():
    parser = argparse.ArgumentParser(prog='world4you', description='An API for World4You DNS Services')
    parser.add_argument('-i', '--interactive', action='store_true', help='Activate interactive mode')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not output log messages')
    parser.add_argument('-u',
                        '--username',
                        metavar='username',
                        type=str,
                        required=True,
                        help='Specify the username to be used')
    parser.add_argument('-p', '--password', metavar='pwd', type=str, help='Specify the password to be used')
    parser.add_argument('-P',
                        '--password-file',
                        metavar='file',
                        type=str,
                        help='Specify the password file to be read the password from')
    parser.add_argument('-o', '--otp', metavar='TOTP', type=str, help='TOTP')
    parser.add_argument('action',
                        metavar='action',
                        type=str,
                        nargs='?',
                        choices=['add', 'update', 'alter', 'delete', 'table', 'csv'],
                        help='The action to be performed')
    parser.add_argument('arg', metavar='arg', nargs='*', type=str, help='Args for the specified action')
    return parser.parse_args()


def main():
    args = parse_args()
    if args.quiet:
        log.setLevel(logging.ERROR)

    username = args.username
    if args.password:
        password = args.password
    elif args.password_file:
        with open(args.password_file) as file:
            password = file.readline().strip()
    else:
        password = getpass.getpass('Password: ', stream=sys.stderr)

    otp = getattr(args, 'otp', None)

    api = MyWorld4YouCli()

    try:
        log.info('Logging in...')
        if api.login(username, password, otp=otp):
            log.info('Successfully logged in')
        else:
            log.error('Invalid credentials')
            sys.exit(5)
    except ConnectionError as e:
        log.error(f'{e}')
        sys.exit(5)

    try:
        if args.interactive:
            api.interactive()
        elif args.action == 'add':
            if not api.add(*args.arg):
                sys.exit(1)
        elif args.action == 'update':
            if not api.update(*args.arg):
                sys.exit(1)
        elif args.action == 'alter':
            if not api.alter(*args.arg):
                sys.exit(1)
        elif args.action == 'delete':
            if not api.delete(*args.arg):
                sys.exit(1)
        elif args.action == 'table':
            if not api.table(*args.arg):
                sys.exit(1)
        elif args.action == 'csv':
            if not api.csv(*args.arg):
                sys.exit(1)
        else:
            log.error("invalid action")
            sys.exit(255)
    except ConnectionError as e:
        log.error(str(e))
        sys.exit(2)
    except IndexError:
        log.error("unable to find resource record")
        sys.exit(3)
    except (KeyError, RuntimeError) as e:
        log.error(str(e))
        sys.exit(3)
    sys.exit(0)
