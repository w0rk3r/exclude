# Objetivo
Detectar o uso de compressão de dados utilizando programas CLI, atividade que geralmente é executada antes do exfil.

# Categorização
Esses Eventos são categorizadas como T1002 / [Data Compressed](https://attack.mitre.org/techniques/T1002/).

# Estratégia
A estratégia vai funcionar da seguinte forma: 

* Monitorar a criação de processos, argumentos de linha de comando.
* Monitorar o uso de cmdlets e a utilização de programas conhecidos de zipping/compressão.
* Alertar se houver qualquer discrepância à atividades normais 

# Contexto Técnico

Atacantes podem comprimir dados, que são coletados anteriormente, com o objetivo de minimizar a quantidade de dados enviados pela rede, para ter maior furtividade em realizar a exfiltração.


# Pontos cegos e suposições
Essa Estratégia depende das seguintes suposições: 

* O EventID 1 do sysmon está configurado corretamente e o envio ao SIEM está sendo realizado.
* O EventID 4688 está configurado para o envio ao SIEM.
* O Log forwarder está encaminhando os Logs para o SIEM.
* SIEM está indexando com sucesso os logs.

Pontos Cegos:

* Atacantes podem usar implementações customizadas de algorítmos para realizar a operação.
* Programas customizados com interface gráfica podem não deixar rastros em eventos de linha de comando.
* Programas que utilizam funções da API do windows para realizar a operação.
* Se os canais de comunicações forem criptografados, arquivos comprimidos podem não ser detectados em trânsito, pois em geral as ferramentas de DLP dependem da análise dos headers do arquivo

# Falsos Positivos
Há circunstâncias nas quais falsos positivos podem ocorrer, porém no momento nenhum foi identificado.

# Prioridade
A prioridade é definida para média sob todas as condições.

# Validação
Validação pode ocorrer realizando as seguintes ações:

### Powershell:
`dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}`
### RAR
`rar a -r #{output_file} #{input_file}`

# Triagem
Em um eventual acionamento desse alerta, os seguintes procedimentos de resposta são recomendados:

* Verificar o processo que executou a ação
* Verificar o usuário em que o processo está sendo executado
* Verificar se os dados que estão sendo comprimidos são dados sensíveis
* Verificar se o usuário tem a permissão de executar a ação

Caso a triagem indique um possível incidente, dar início.

# Recursos Adicionais
* [Data Compressed](https://attack.mitre.org/techniques/T1002/)
