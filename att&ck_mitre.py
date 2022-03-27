import pandas as pd
import json
from attackcti import attack_client
from collections import OrderedDict


def generate_ttp(prefix_name, extensions=['json','csv']):

    """
    Sub functions to be used for each
    attack mitre layers
    """
    def generate_attackcti_ttp_dict(attackcti_tactics):
        print("start generate_attackcti_ttp_dict...")

        def get_layer(src_name):
            if src_name=="mitre-attack":
                return "enterprise"
            elif src_name=="mitre-ics-attack":
                return "ics"
            elif src_name=="mitre-mobile-attack":
                return "mobile"
            else:
                return "Nan"

        def get_references(ref_list):
            ref_str=""
            for ref in ref_list:
                try:
                    ref_str += ref['description']+'['+ref["url"]+'] '
                except:
                    pass
            return ref_str

        ttp={}
        for tactic in attackcti_tactics:   
            ttp.update({
                tactic['name'] : {
                    "techniques": [
                        {
                            "technique_name": technique['name'],
                            "technique_id": technique['external_references'][0]['external_id'],
                            "layer": get_layer(technique['external_references'][0]['source_name']),
                            "platforms":technique['x_mitre_platforms'],
                            "description": technique['description'],
                            "detection": technique['x_mitre_detection'] if ('x_mitre_detection' in technique) else '',
                            "references": get_references(technique['external_references']),
                            "created": str(technique['created']).split(' ')[0]
                        } for technique in lift.get_techniques_by_tactic( tactic['name'].replace(" ", "-"), case=False)
                        if 'x_mitre_deprecated' not in technique 
                        and technique['external_references'][0]['source_name'] != "mitre-mobile-attack"
                    ]
                }
            })
        print("Function 'generate_attackcti_ttp_dict' done")
        return ttp
                                

    """
    Generates two dictionaries using the attackcti API
    """
    lift = attack_client()

    ics_tactics = lift.get_ics_tactics()
    ent_tactics = lift.get_enterprise_tactics()

    ttp_ics = generate_attackcti_ttp_dict(ics_tactics)
    ttp_ent = generate_attackcti_ttp_dict(ent_tactics)


    """
    Merge two dictonaries into one.
    INFO: tactic name was set as a key then changed 
    back to a value in order to take the most benefit
    (no duplicate, possibility to sort) from the python 
    update function and avoid dealing with nested dict 
    in nested list. 
    """
    ttp_ics.update(ttp_ent)
    ttp_tmp = OrderedDict(sorted(ttp_ics.items()))

    tactics_list = []
    rows=[]
    for k,v in ttp_tmp.items():
        if 'csv' in extensions:
            for technique in v['techniques']:
                row = {
                    "tactic": k,
                    "technique": technique['technique_name'],
                    "id": technique['technique_id'],
                    "platforms": ','.join(technique['platforms']),
                    "layer": technique['layer'],
                    "created": technique['created']
                }
                rows.append(row)

        if 'json' in extensions:
            tactic_dic = {
                "tactic_name": k,
                "techniques": [
                    {
                        "technique_name": technique['technique_name'],
                        "technique_id": technique['technique_id'],
                        "layer": technique['layer'],
                        "platforms":technique['platforms'],
                        "description": technique['description'],
                        "detection": technique['detection'],
                        "references": technique['references'],
                        "created": technique['created']
                    } for technique in v['techniques']
                ]
            }
            tactics_list.append(tactic_dic)

    ttp = { "tactics": tactics_list  }

    # Save output file
    # ----------------
    if 'csv' in extensions :
        df = pd.DataFrame(rows)
        df.to_csv(prefix_name+'.csv', sep='|', index=False)

    if 'json' in extensions :
        with open(prefix_name+'.json', 'w', encoding="utf-8", newline='\r\n') as output:
            json.dump(ttp, output, ensure_ascii=False, indent=4)



def generate_relations(output_csv="data/relations.csv", output_json="data/relations.json"):

    relations = {}
    lift = attack_client()
    groups = lift.get_groups()

    with open(output_json, 'w') as output1:

        with open(output_csv, 'w') as output2:

            print("Starting parsing %d groups..." % len(groups))
            output2.write("group|software|technique|tid\n")
            groups_list=[]
            count=0
            for group in groups:
                softwares = lift.get_software_used_by_group(group)
                softwares_list = []

                for software in softwares:
                    techniques = lift.get_techniques_used_by_software(software)
                    techniques_list=[]

                    for technique in techniques:
                        techniques_list.append({"name": technique['name'], "id": technique['external_references'][0]['external_id']})
                        print("[group]: %s [software]: %s [technique]: %s" % (group['name'], software['name'], technique['name']) )
                        output2.write(group['name']+"|"+software['name']+"|"+technique['name']+"|"+technique['external_references'][0]['external_id']+'\n')
                        print(technique['external_references'][0]['external_id'])
                    
                    softwares_list.append({ "name":software['name'], "techniques": techniques_list })
                
                groups_list.append({"name": group['name'], "softwares": softwares_list})

                count+=1
                if count==2:
                    pass
                    #break

            relations.update( {"groups": groups_list} )

        json.dump(relations, output1, ensure_ascii=False, indent=4)


    if 1==1:
        # Adding aliases to relations.json and relations.csv files
        # This part is independant from the geneartion of relations.json 
        # as it requieres the dl of a groups.json intermediate file. 

        # create groups.json file
        lift = attack_client()
        groups = lift.get_groups()

        with open('groups.json', 'w') as output1:
            print(len(groups))
            groups_str = '\n'.join(map(str, groups))
            output1.write( groups_str )

        # openning groups
        with open('groups.json') as json_file:
            groups_list = json.load(json_file)

        groups_dict = {"groups": groups_list}

        df = pd.read_csv(output_csv, delimiter='|', error_bad_lines=False)
        with open(output_json) as json_file:
            relations_dict = json.load(json_file)

                        
        for group_r in relations_dict['groups']:
            for group_g in groups_dict["groups"]:
                aliases = []
                if group_g['name'] == group_r['name']:
                    try:
                        print(group_g['name'], group_g['aliases'])
                        aliases = group_g['aliases']
                    except:
                        pass
                    df.loc[df['group'].str.contains(group_g['name'], na=False), 'aliases'] = ','.join(aliases) # add column extra with content if condition respected
                    group_r.update({
                        "aliases": aliases,
                    })
        #            group_r.update({"aliases": group_g['aliases']})

        with open(output_json, 'w') as output:
            json.dump(relations_dict, output, ensure_ascii=False, indent=4)

        df.to_csv(output_csv, sep='|', index=False)

    print("done")
        #print( relations )


def merge_ttp_relations(ttp_path="data/ttp_example.csv", relations_path="data/relations_example.csv", output_csv="data/ttp_relations_merged.csv"):
    df1 = pd.read_csv(ttp_path, sep='|')
    df2 = pd.read_csv(relations_path, sep='|')
    result = pd.merge(df1, df2, how='inner', on=['technique','id'])
    result.to_csv(output_csv, sep='|', index=False)


if __name__ == '__main__':

    if 1==0:
        # generate a ttp.json/.csv file based on the 
        # mitre Att&ck informations accessible 
        # from the package 'attackcti'
        # INFO : approx 5min to generate
        generate_ttp(
            prefix_name='data/ttp', 
            extensions=['json','csv'])

    if 1==0:
        # generate relations between techniques/subtechnique 
        # software and groups from the attack mitre
        # INFO : /!\ takes 12 hours to generate...
        generate_relations(
            output_csv="data/relations.csv", 
            output_json="data/relations.json")

    if 1==1:
        # merge columns with pivot [technique, id]
        # from tt.csv        => tactic|technique|id|platforms|layer|created
        # from relations.csv => group|software|technique|id|aliases
        merge_ttp_relations(
            ttp_path="data/ttp.csv", 
            relations_path="data/relations.csv",
            output_csv="data/ttp_relations_merged.csv")