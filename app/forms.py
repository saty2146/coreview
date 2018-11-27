from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, SelectField, RadioField
from wtforms import TextAreaField, TextField, IntegerField, ValidationError, DateField, validators
from wtforms.validators import DataRequired, IPAddress, NumberRange, Optional
import ipaddress,yaml
from boxes import *

def load_six_asr():

    with open('app/six_asr.yml', 'r') as f:
        six_asr = yaml.safe_load(f)
        ifaces = six_asr['ifaces']
    
    ids = [i for i in range(len(ifaces))]
    id_ifaces = list(zip(ids, ifaces))

    return id_ifaces

def vnet_ipv4(form, field):
    if (
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'46.229.224.0/20') and 
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'81.89.48.0/20') and 
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'93.184.64.0/20') and
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'109.74.144.0/20') and
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'217.73.16.0/20') and
            ipaddress.ip_address(field.data) not in ipaddress.ip_network(u'185.176.72.0/22')
            ):
        raise ValidationError('This is not VNET IP address')

class PortchannelForm(FlaskForm):
    portchannel = SelectField('portchannel', coerce=int, choices=[(1,'Yes'),(0,'No')])
    porttype = SelectField('porttype', coerce=int, choices = [(0, 'Access'), (1, 'Trunk')])
    clientid = IntegerField('clientid', validators=[Optional()])
    company = StringField('company', validators=[DataRequired()])
    iface1 = SelectField('iface1', coerce=int)
    iface2 = SelectField('iface2', coerce=int)
    vlans = StringField('vlans', validators=[DataRequired()])
    configuration = TextAreaField('configuration', default="Empty")

class PeeringForm(FlaskForm):
    peering = SelectField('peering', coerce=int, choices=[(1,'SIX'),(2,'NIX.CZ'),(3,'NIX.SK'),(4,'AMS-IX')])
    description = StringField('description', validators=[DataRequired()])
    asn = IntegerField('asn', validators=[Optional()])
    ipv4 = StringField('ipv4', validators=[DataRequired(),IPAddress(ipv4=True, ipv6=False, message=None)])
    ipv6 = StringField('ipv6', validators=[DataRequired(), IPAddress(ipv4=False, ipv6=True, message=None)])
    prefixlimipv4 = IntegerField('prefixlimipv4', validators=[DataRequired(), NumberRange(min=1, max=None, message=None)])
    prefixlimipv6 = IntegerField('prefixlimipv6', validators=[DataRequired(),NumberRange(min=1, max=None, message=None)])

class L2circuitForm(FlaskForm):
    iface = SelectField('iface', coerce=int, choices = load_six_asr())
    clientid = IntegerField('clientid', validators=[Optional()])
    company = StringField('company', validators=[DataRequired()])
    vlan = IntegerField('vlan', validators=[DataRequired()])
    configuration = TextAreaField('configuration', default="Empty")

class VxlanForm(FlaskForm):
    vlanid = IntegerField('vlan', validators=[DataRequired(), NumberRange(min=1, max=9999, message='1-9999')])
    vlanname = StringField('vlanname', validators=[DataRequired()])

class PppoeForm(FlaskForm):
    pppoe = StringField('pppoe account', [validators.DataRequired(), validators.Regexp('\d+@ftth.vnet.sk', message="Invalid format")])

class DslForm(FlaskForm):
    dsl = StringField('dsl account', [validators.DataRequired(), validators.Regexp('\S+@\S+', message="Invalid format")])

class RtbhForm(FlaskForm):
    ipv4 = StringField('ipv4', validators=[DataRequired(),IPAddress(ipv4=True, ipv6=False, message=None),vnet_ipv4])
    action = SelectField('action', coerce=int, choices=[(1,'announce'),(0,'withdraw')])

class ScrubbingForm(FlaskForm):
    action = SelectField('action', coerce=int, choices=[(1,'announce'),(0,'withdraw')])
    network = SelectField('network', coerce=int, choices=[(0,''),(1,'86.110.233.0/24'),(2,'46.229.237.0/24'),(3,'81.89.54.0/24'),(4,'93.184.75.0/24'),(5,'185.176.75.0/24')])

class DateForm(FlaskForm):
    dt = DateField('dt', format="%d/%m/%Y")
    box = SelectField('box', coerce=int, choices=box_form_choice)
    severity = SelectField('severity', coerce=int, choices=severity_form_choice)
