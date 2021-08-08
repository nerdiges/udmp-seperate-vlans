#!/bin/sh

##############################################################################################
#
# Configuration
#

# interfaces listed in exclude will not be separted and can still access
# the other VLANs. Multiple interfaces are to be separated by spaces.
exclude="br20"

# Add rule to allow established and related network traffic coming in to LAN interface
allow_related_lan=true

# Add rule to allow established and related network traffic coming in to guest interface
allow_related_guest=true

#
##############################################################################################


##############################################################################################
#
# No further changes should be necessary beyond this line.
#

# set scriptname
me=$(basename $0)


# Check if script runs directly after boot. If so, wait 10 seconds to ensure all is up and running.
uptimeMinutes=`cat /proc/uptime | awk '{print $1}'`
if [ ${uptimeMinutes::-3} -lt 300 ]
        then
                logger "$me: Script running after (re)boot."
                sleep 10
        else
                logger "$me: Script startet via Cron-Job."
fi


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# LAN separation
#

# Get list of relevant LAN interfaces and total number of interfaces
lan_if=$(iptables --list-rules UBIOS_FORWARD_IN_USER | awk '/-j UBIOS_LAN_IN_USER/ { print $4 }')
lan_if_count=$(echo $lan_if | wc -w)

# prepare ip(6)tables chains lan_separation
iptables -N lan_separation &> /dev/null && logger "$me: IPv4 chain created (lan_separation)"
ip6tables -N lan_separation &> /dev/null && logger "$me: IPv6 chain created (lan_separation)"

# add allow related/established to UBIOS_LAN_IN_USER if requested
if [ $allow_related_lan == "true" ]; then
    rule="-A UBIOS_LAN_IN_USER -m conntrack --ctstate RELATED,ESTABLISHED.*-j RETURN"
    iptables --list-rules | grep -e "$rule" &> /dev/null ||
        iptables -I UBIOS_LAN_IN_USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
    ip6tables --list-rules | grep -e "$rule" &> /dev/null ||
        ip6tables -I UBIOS_LAN_IN_USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
fi

# LAN separation only necessary if at least 2 LANs are configured
if [ $lan_if_count -gt 1 ]; then

    # Add missing rules to chain lan_separation
    for i in $lan_if; do
        case "$exclude " in
            *"$i "*)
                logger "$me: Excluding $i from VLAN separation as requested in config."
                ;;

            *)
                for o in $lan_if; do
                    if ! [ "$i" == "$o" ]; then
                        rule="-A lan_separation -i $i -o $o -j REJECT"
                        iptables --list-rules | grep -e "$rule" &> /dev/null || iptables $rule
                        ip6tables --list-rules | grep -e "$rule" &> /dev/null || ip6tables $rule
                    fi
                done
                ;;
        esac
    done

    # Remove all rules that block traffic originating from excluded interfaces
    # (should only be necessary if $exclude is changed)
    rules=$(iptables -L lan_separation -v --line-number | grep -E "^[0-9]+" | sort -r)
    for e in $exclude; do
        for r in $rules; do
            rnum=$(echo $r | grep -e "-- *$e " | awk '{ print $1 }')
            if [ $rnum ]; then
                iptables -D lan_separation $rnum && logger "$me: Removing rule $rnum from VLAN separation ($r)."
            fi
        done
    done

    # add IPv4 rule to include rules in chain lan_separation
    if ! iptables --list-rules | grep -e "-A UBIOS_LAN_IN_USER -j lan_separation" &> /dev/null; then
        rules=$(iptables -L UBIOS_LAN_IN_USER --line-numbers | awk 'END { print $1 }')
        v4_idx=$(expr $rules - $lan_if_count)
        iptables -I UBIOS_LAN_IN_USER $v4_idx -j lan_separation
    fi

    # add IPv6 rule to include rules in chain lan_separation
    if ! ip6tables --list-rules | grep -e "-A UBIOS_LAN_IN_USER -j lan_separation" &> /dev/null; then
        rules=$(ip6tables -L UBIOS_LAN_IN_USER --line-numbers | awk 'END { print $1 }')
        v6_idx=$(expr $rules - $lan_if_count)
        ip6tables -I UBIOS_LAN_IN_USER $v6_idx -j lan_separation
    fi
else
    logger "$me: Just one LAN interface detected. No filters implemented. Starting clean up..."

    iptables -D UBIOS_LAN_IN_USER -j lan_separation && logger "$me: IPv4 firewall rule to include chain lan_separation deleted."
    iptables -F lan_separation && logger "$me: Existing IPv4 chain lan_separation flushed."
    # do not delete chain, as it is used to implement lan > guest separation
    #iptables -X lan_separation && logger "$me: Existing IPv4 chain lan_separation deleted."

    ip6tables -D UBIOS_LAN_IN_USER -j lan_separation && logger "$me: IPv6 firewall rule to include chain lan_separation deleted."
    ip6tables -F lan_separation && logger "$me: Existing IPv6 chain lan_separation flushed."
    # do not delete chain, as it is used to implement lan > guest separation
    #ip6tables -X lan_separation && logger "$me: Existing IPv6 chain lan_separation deleted."
fi


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# guest separation
#

# Get list of relevant guest interfaces and total number of interfaces
guest_if=$(iptables --list-rules UBIOS_FORWARD_IN_USER | awk '/-j UBIOS_GUEST_IN_USER/ { print $4 }')
guest_if_count=$(echo $guest_if | wc -w)

# add allow related/established to UBIOS_LAN_IN_USER if requested
if [ $allow_related_guest == "true" ]; then
    rule="-A UBIOS_GUEST_IN_USER -m conntrack --ctstate RELATED,ESTABLISHED.*-j RETURN"
    iptables --list-rules | grep -e "$rule" &> /dev/null ||
        iptables -I UBIOS_GUEST_IN_USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
    ip6tables --list-rules | grep -e "$rule" &> /dev/null ||
        ip6tables -I UBIOS_GUEST_IN_USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
fi

# LAN separation only necessary if at least 2 LANs are configured
if [ $guest_if_count -gt 1 ]; then

    # prepare ip(6)tables chains
    iptables -N guest_separation &> /dev/null && logger "$me: IPv4 chain created (guest_separation)"
    ip6tables -N guest_separation &> /dev/null && logger "$me: IPv6 chain created (guest_separation)"

    # Add missing rules to chain guest_separation
    for i in $guest_if; do
        case "$exclude " in
            *"$i "*)
                logger "$me: Excluding $i from VLAN separation as requested in config."
                ;;

            *)
                for o in $guest_if; do
                    if ! [ "$i" == "$o" ]; then
                        rule="-A guest_separation -i $i -o $o -j REJECT"
                        iptables --list-rules | grep -e "$rule" &> /dev/null || iptables $rule
                        ip6tables --list-rules | grep -e "$rule" &> /dev/null || ip6tables $rule
                    fi
                done
                ;;
        esac
    done

    # Remove all rules that block traffic originating from excluded interfaces
    # (should only be necessary if $exclude is changed)
    rules=$(iptables -L guest_separation -v --line-number | grep -E "^[0-9]+" | sort -r)
    for e in $exclude; do
        for r in $rules; do
            rnum=$(echo $r | grep -e "-- *$e " | awk '{ print $1 }')
            if [ $rnum ]; then
                iptables -D guest_separation $rnum && logger "$me: Removing rule $rnum from VLAN separation ($r)."
            fi
        done
    done

    if ! iptables --list-rules | grep -e "-A UBIOS_GUEST_IN_USER -j guest_separation" &> /dev/null ; then
        # add IPv4 rule to include rules in chain guest_separation
        rules=$(iptables -L UBIOS_GUEST_IN_USER --line-numbers | awk 'END { print $1 }')
        v4_idx=$(expr $rules - $guest_if_count)
        iptables -I UBIOS_GUEST_IN_USER $v4_idx -j guest_separation
    fi

    # add IPv6 rule to include rules in chain guest_separation
    if ! ip6tables --list-rules | grep -e "-A UBIOS_GUEST_IN_USER -j guest_separation" &> /dev/null; then
        rules=$(ip6tables -L UBIOS_GUEST_IN_USER --line-numbers | awk 'END { print $1 }')
        v6_idx=$(expr $rules - $guest_if_count)
        ip6tables -I UBIOS_GUEST_IN_USER $v6_idx -j guest_separation
    fi
else
    logger "$me: Just one guest interface detected. No filters implemented. Starting clean up..."

    iptables -D UBIOS_GUEST_IN_USER -j guest_separation && logger "$me: IPv4 firewall rule to include chain guest_separation deleted."
    iptables -F guest_separation && logger "$me: Existing IPv4 chain guest_separation flushed."
    iptables -X guest_separation && logger "$me: Existing IPv4 chain guest_separation deleted."

    ip6tables -D UBIOS_GUEST_IN_USER -j guest_separation && logger "$me: IPv6 firewall rule to include chain guest_separation deleted."
    ip6tables -F guest_separation && logger "$me: Existing IPv6 chain guest_separation flushed."
    ip6tables -X guest_separation && logger "$me: Existing IPv6 chain guest_separation deleted."
fi


# add rules to fix packet leakage from LAN > guest
for i in $lan_if; do
    for o in $guest_if; do
        rule="-A lan_separation -i $i -o $o -j REJECT"
        iptables --list-rules | grep -e "$rule" &> /dev/null || iptables $rule
        ip6tables --list-rules | grep -e "$rule" &> /dev/null || ip6tables $rule
    done
done


# Check if cron job exists
if ls /etc/cron.d/separate-vlans > /dev/null 2>&1
        then
                logger "$me: Cron job exists"
        else
                echo "*/2 * * * * /mnt/data/on_boot.d/21-separate-vlans.sh" > /etc/cron.d/separate-vlans
                logger "$me: Cron job created"
                /etc/init.d/crond restart
fi
